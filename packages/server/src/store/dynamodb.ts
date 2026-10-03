// A store adapter for Amazon DynamoDB, built only on madAuth's public API, exactly as a custom adapter would be.
// Published as `@madauth/server/dynamodb`. It needs the `@aws-sdk/client-dynamodb` package, which AWS Lambda's
// Node.js runtimes already contain.
//
// All models share one table with the string keys `pk` and `sk`:
//
//   record        pk = r|<model>|<id>               sk = #      the record's fields
//   unique value  pk = u|<model>|<field>|<value>    sk = #      ref = <id>
//   index entry   pk = i|<model>|<field>|<value>    sk = <id>
//
// A record and its unique values and index entries are always written in one transaction, and every read is
// strongly consistent. So a record can be read right after it was written, which a global secondary index
// would not guarantee.
import type { AttributeValue, DynamoDBClient, TransactWriteItem } from '@aws-sdk/client-dynamodb';
import { madauthSchema, type FieldDef, type Row, type StoreAdapter, type Value, type Where } from './schema.js';

export interface DynamoDbAdapterOptions {
  /** The table, with the partition key `pk` and the sort key `sk` (both strings). */
  tableName: string;
  /** Default: a client with the region and credentials of the environment. */
  client?: Pick<DynamoDBClient, 'send'>;
}

type Sdk = typeof import('@aws-sdk/client-dynamodb');
type Fields = Record<string, FieldDef>;
type Item = Record<string, AttributeValue>;

/** Attribute names and values of an expression; every field goes through a placeholder (`name` and `key` are reserved words). */
interface Expression {
  text: string;
  names: Record<string, string>;
  values: Item;
}

const SORT_KEY = '#';
/** How often a write is sent again when another write on the same record was in the way. */
const MAX_RETRIES = 8;
/** Why DynamoDB cancels a transaction although nothing is wrong with it; such a transaction is sent again. */
const RETRYABLE_REASONS = ['TransactionConflict', 'ThrottlingError', 'ProvisionedThroughputExceeded'];
const RETRYABLE_ERRORS = ['TransactionConflictException', 'TransactionInProgressException'];

const recordKey = (model: string, id: string): Item => ({ pk: { S: `r|${model}|${id}` }, sk: { S: SORT_KEY } });
const uniqueKey = (model: string, field: string, value: Value): Item => ({
  pk: { S: `u|${model}|${field}|${String(value)}` },
  sk: { S: SORT_KEY },
});
const indexPartition = (model: string, field: string, value: Value): string => `i|${model}|${field}|${String(value)}`;
const indexKey = (model: string, field: string, value: Value, id: string): Item => ({
  pk: { S: indexPartition(model, field, value) },
  sk: { S: id },
});

function toAttribute(value: Value): AttributeValue {
  if (value === null) return { NULL: true };
  if (typeof value === 'string') return { S: value };
  if (typeof value === 'number') return { N: String(value) };
  return { BOOL: value };
}

function fromAttribute(attribute: AttributeValue | undefined): Value {
  if (attribute?.S !== undefined) return attribute.S;
  if (attribute?.N !== undefined) return Number(attribute.N);
  if (attribute?.BOOL !== undefined) return attribute.BOOL;
  return null;
}

function fieldsOf(model: string): Fields {
  const fields = (madauthSchema.models as Record<string, { fields: Fields }>)[model]?.fields;
  if (!fields) throw new Error(`Unknown model "${model}"`);
  return fields;
}

function checkFields(fields: Fields, names: string[]): void {
  for (const name of names) if (!fields[name]) throw new Error(`Unknown field "${name}"`);
}

function primaryKeyOf(fields: Fields): string {
  return Object.keys(fields).find((name) => fields[name].primaryKey)!;
}

function toRow(fields: Fields, item: Item): Row {
  return Object.fromEntries(Object.keys(fields).map((name) => [name, fromAttribute(item[name])]));
}

function matches(row: Row, where: Where): boolean {
  return Object.entries(where).every(([field, value]) => row[field] === value);
}

/** The condition that a record still exists and still matches `where`, so a write counts for one request only. */
function stillMatches(where: Where): Expression {
  const names: Record<string, string> = {};
  const values: Item = {};
  const parts = ['attribute_exists(pk)'];
  Object.entries(where).forEach(([field, value], i) => {
    names[`#w${i}`] = field;
    values[`:w${i}`] = toAttribute(value);
    // A field that was never written is as empty as one that holds null.
    parts.push(value === null ? `(attribute_not_exists(#w${i}) OR #w${i} = :w${i})` : `#w${i} = :w${i}`);
  });
  return { text: parts.join(' AND '), names, values };
}

type WriteOutcome = 'written' | 'refused' | { retry: unknown };

/** Sorts a failed write: a condition that did not hold, a clash with another write, or a real error (thrown). */
function failedWrite(error: unknown): WriteOutcome {
  const { name, CancellationReasons } = error as { name?: string; CancellationReasons?: { Code?: string }[] };
  if (name === 'ConditionalCheckFailedException') return 'refused';
  if (name && RETRYABLE_ERRORS.includes(name)) return { retry: error };
  if (name === 'TransactionCanceledException') {
    const reasons = (CancellationReasons ?? []).map((r) => r.Code ?? 'None').filter((code) => code !== 'None');
    if (reasons.includes('ConditionalCheckFailed')) return 'refused';
    if (reasons.length && reasons.every((code) => RETRYABLE_REASONS.includes(code))) return { retry: error };
  }
  throw error;
}

const pause = (attempt: number) =>
  new Promise((resolve) => setTimeout(resolve, Math.random() * Math.min(25 * 2 ** attempt, 400)));

/**
 * Stores madAuth's records in one DynamoDB table. Create the table yourself, with the partition key `pk`
 * and the sort key `sk`, both of type string (see "DynamoDB" in docs/server.md).
 *
 * A filter must contain the record's id, a unique field or an indexed field: the adapter never scans the
 * table. Unique and indexed fields can't be changed by `update`.
 */
export function createDynamoDbAdapter(options: DynamoDbAdapterOptions): StoreAdapter {
  const { tableName } = options;
  // Loaded on first use, so importing madAuth works without the AWS SDK.
  let loading: Promise<{ sdk: Sdk; client: Pick<DynamoDBClient, 'send'> }> | undefined;
  const aws = () =>
    (loading ??= import('@aws-sdk/client-dynamodb').then((sdk) => ({
      sdk,
      client: options.client ?? new sdk.DynamoDBClient({}),
    })));

  /** Sends a write. Resolves to false if its condition did not hold, i.e. nothing was written. */
  const write = async (send: () => Promise<unknown>): Promise<boolean> => {
    for (let attempt = 0; ; attempt++) {
      const outcome = await send().then((): WriteOutcome => 'written', failedWrite);
      if (outcome === 'written') return true;
      if (outcome === 'refused') return false;
      if (attempt === MAX_RETRIES) throw outcome.retry;
      await pause(attempt);
    }
  };

  const transact = async (items: TransactWriteItem[]): Promise<boolean> => {
    const { sdk, client } = await aws();
    // A new command per attempt, so each one gets its own idempotency token.
    return write(() => client.send(new sdk.TransactWriteItemsCommand({ TransactItems: items })));
  };

  const getItem = async (key: Item): Promise<Item | undefined> => {
    const { sdk, client } = await aws();
    return (await client.send(new sdk.GetItemCommand({ TableName: tableName, Key: key, ConsistentRead: true }))).Item;
  };

  const getRecord = async (model: string, fields: Fields, id: string): Promise<Row | null> => {
    const item = await getItem(recordKey(model, id));
    return item ? toRow(fields, item) : null;
  };

  const idsOfIndex = async (model: string, field: string, value: Value): Promise<string[]> => {
    const { sdk, client } = await aws();
    const ids: string[] = [];
    let next: Item | undefined;
    do {
      const page = await client.send(
        new sdk.QueryCommand({
          TableName: tableName,
          KeyConditionExpression: 'pk = :pk',
          ExpressionAttributeValues: { ':pk': { S: indexPartition(model, field, value) } },
          ProjectionExpression: 'sk',
          ConsistentRead: true,
          ExclusiveStartKey: next,
        }),
      );
      for (const item of page.Items ?? []) if (item.sk?.S) ids.push(item.sk.S);
      next = page.LastEvaluatedKey;
    } while (next);
    return ids;
  };

  /** The records matching `where`, found by id, by a unique field or by an indexed field. */
  const find = async (model: string, where: Where): Promise<Row[]> => {
    const fields = fieldsOf(model);
    checkFields(fields, Object.keys(where));
    const given = (name: string) => where[name] !== undefined && where[name] !== null;
    const primaryKey = primaryKeyOf(fields);
    const unique = Object.keys(fields).find((name) => fields[name].unique && given(name));
    const indexed = Object.keys(fields).find((name) => fields[name].index && given(name));

    let ids: string[];
    if (given(primaryKey)) {
      ids = [String(where[primaryKey])];
    } else if (unique) {
      const ref = (await getItem(uniqueKey(model, unique, where[unique])))?.ref?.S;
      ids = ref ? [ref] : [];
    } else if (indexed) {
      ids = await idsOfIndex(model, indexed, where[indexed]);
    } else {
      throw new Error(
        `The DynamoDB adapter can't find "${model}" records by ${Object.keys(where).join(', ') || 'nothing'}: ` +
          'the filter needs the id, a unique field or an indexed field.',
      );
    }
    const rows = await Promise.all(ids.map((id) => getRecord(model, fields, id)));
    return rows.filter((row): row is Row => row !== null && matches(row, where));
  };

  /** The keys of a record's unique values and index entries. */
  const derivedKeys = (model: string, fields: Fields, row: Row, id: string): Item[] =>
    Object.keys(fields).flatMap((name) => {
      const value = row[name];
      if (value === undefined || value === null) return [];
      return [
        ...(fields[name].unique ? [uniqueKey(model, name, value)] : []),
        ...(fields[name].index ? [indexKey(model, name, value, id)] : []),
      ];
    });

  return {
    async create(model, data) {
      const fields = fieldsOf(model);
      checkFields(fields, Object.keys(data));
      const primaryKey = primaryKeyOf(fields);
      const id = data[primaryKey];
      if (typeof id !== 'string' || !id) throw new Error(`A "${model}" record needs a "${primaryKey}"`);

      const record: Item = { ...recordKey(model, id) };
      for (const [field, value] of Object.entries(data)) record[field] = toAttribute(value);
      const unused = 'attribute_not_exists(pk)';
      return transact([
        { Put: { TableName: tableName, Item: record, ConditionExpression: unused } },
        ...derivedKeys(model, fields, data, id).map((key) =>
          // A unique value refers to its record and may not be taken yet; an index entry is only a key.
          key.pk.S!.startsWith('u|')
            ? { Put: { TableName: tableName, Item: { ...key, ref: { S: id } }, ConditionExpression: unused } }
            : { Put: { TableName: tableName, Item: key } },
        ),
      ]);
    },

    async findOne(model, where) {
      return (await find(model, where))[0] ?? null;
    },

    async findMany(model, where, opts = {}) {
      const rows = await find(model, where);
      return opts.limit === undefined ? rows : rows.slice(0, Math.max(0, Math.floor(opts.limit)));
    },

    async update(model, where, patch) {
      const fields = fieldsOf(model);
      const changes = Object.entries(patch);
      checkFields(fields, [...Object.keys(where), ...Object.keys(patch)]);
      for (const [field] of changes) {
        if (fields[field].primaryKey || fields[field].unique || fields[field].index) {
          throw new Error(`The DynamoDB adapter can't change "${field}" of a "${model}" record: it is a key.`);
        }
      }
      if (!changes.length) return 0;

      const primaryKey = primaryKeyOf(fields);
      const condition = stillMatches(where);
      const names = { ...condition.names };
      const values = { ...condition.values };
      const assignments = changes.map(([field, value], i) => {
        names[`#p${i}`] = field;
        values[`:p${i}`] = toAttribute(value);
        return `#p${i} = :p${i}`;
      });
      // With the id in the filter, the condition alone decides; there is nothing to look up first.
      const byId = where[primaryKey];
      const ids =
        byId !== undefined && byId !== null
          ? [String(byId)]
          : (await find(model, where)).map((row) => String(row[primaryKey]));
      // A transaction, not an UpdateItem: its idempotency token makes the SDK's retry after a lost response
      // succeed again instead of failing its own condition, so the count stays exact.
      const written = await Promise.all(
        ids.map((id) =>
          transact([
            {
              Update: {
                TableName: tableName,
                Key: recordKey(model, id),
                UpdateExpression: `SET ${assignments.join(', ')}`,
                ConditionExpression: condition.text,
                ExpressionAttributeNames: names,
                ExpressionAttributeValues: values,
              },
            },
          ]),
        ),
      );
      return written.filter(Boolean).length;
    },

    async delete(model, where) {
      const fields = fieldsOf(model);
      const primaryKey = primaryKeyOf(fields);
      const condition = stillMatches(where);
      // One transaction per record: its condition decides which of several concurrent deletes counts.
      const deleted = await Promise.all(
        (await find(model, where)).map((row) => {
          const id = String(row[primaryKey]);
          return transact([
            {
              Delete: {
                TableName: tableName,
                Key: recordKey(model, id),
                ConditionExpression: condition.text,
                ExpressionAttributeNames: condition.names,
                ExpressionAttributeValues: condition.values,
              },
            },
            ...derivedKeys(model, fields, row, id).map((key) => ({ Delete: { TableName: tableName, Key: key } })),
          ]);
        }),
      );
      return deleted.filter(Boolean).length;
    },
  };
}
