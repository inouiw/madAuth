import { CreateTableCommand, DeleteTableCommand, DynamoDBClient, waitUntilTableExists } from '@aws-sdk/client-dynamodb';
import { readFileSync } from 'node:fs';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { storeAdapterContract } from '../testing.js';
import { createDynamoDbAdapter } from './dynamodb.js';

// The contract needs a database. Start DynamoDB Local and point the tests to it:
//   docker run --rm -p 8000:8000 amazon/dynamodb-local
//   DYNAMODB_TEST_ENDPOINT=http://localhost:8000 npm test
// DYNAMODB_TEST_ENDPOINT=aws uses the real service with the environment's region and credentials.
const endpoint = process.env.DYNAMODB_TEST_ENDPOINT;

describe.skipIf(!endpoint)('DynamoDB adapter with a database', () => {
  const tableName = `madauth_test_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  const client =
    endpoint === 'aws'
      ? new DynamoDBClient({})
      : new DynamoDBClient({ endpoint, region: 'local', credentials: { accessKeyId: 'local', secretAccessKey: 'local' } });

  beforeAll(async () => {
    await client.send(
      new CreateTableCommand({
        TableName: tableName,
        AttributeDefinitions: [
          { AttributeName: 'pk', AttributeType: 'S' },
          { AttributeName: 'sk', AttributeType: 'S' },
        ],
        KeySchema: [
          { AttributeName: 'pk', KeyType: 'HASH' },
          { AttributeName: 'sk', KeyType: 'RANGE' },
        ],
        BillingMode: 'PAY_PER_REQUEST',
      }),
    );
    await waitUntilTableExists({ client, maxWaitTime: 60 }, { TableName: tableName });
  }, 90_000);

  afterAll(async () => {
    await client.send(new DeleteTableCommand({ TableName: tableName }));
  });

  storeAdapterContract({ describe, it, expect }, () => createDynamoDbAdapter({ tableName, client }));

  it('leaves no unique values or index entries behind when records are deleted', async () => {
    const store = createDynamoDbAdapter({ tableName, client });
    const account = {
      id: 'acc_reuse',
      userId: 'usr_reuse',
      key: 'password:usr_reuse',
      secret: null,
      failedAttempts: 0,
      lockedUntil: 0,
      createdAt: 1,
    };
    await store.create('account', account);
    expect(await store.delete('account', { id: account.id })).toBe(1);

    // The same unique value is free again, and the index holds only the new record.
    expect(await store.create('account', { ...account, id: 'acc_reuse_2' })).toBe(true);
    expect((await store.findMany('account', { userId: 'usr_reuse' })).map((row) => row.id)).toEqual(['acc_reuse_2']);
  });
});

/** An AWS SDK error as the adapter sees it. */
function awsError(name: string, reasons?: string[]): Error {
  return Object.assign(new Error(name), { name, CancellationReasons: reasons?.map((Code) => ({ Code })) });
}

interface Sent {
  command: string;
  input: any;
}

/** A client that answers each call with the next entry: an output, or an error to throw. */
function scriptedClient(answers: (object | Error)[]) {
  const sent: Sent[] = [];
  const client = {
    async send(command: { constructor: { name: string }; input: unknown }) {
      sent.push({ command: command.constructor.name, input: command.input });
      const answer = answers.shift() ?? {};
      if (answer instanceof Error) throw answer;
      return answer;
    },
  } as unknown as Pick<DynamoDBClient, 'send'>;
  return { client, sent };
}

const user = {
  id: 'usr_1',
  email: 'Ada@example.com',
  emailNormalized: 'ada@example.com',
  emailVerified: true,
  name: null,
  sessionVersion: 0,
  lastMailAt: 0,
  wrongCodes: 0,
  createdAt: 1,
};

const userItem = {
  pk: { S: 'r|user|usr_1' },
  sk: { S: '#' },
  id: { S: 'usr_1' },
  email: { S: 'Ada@example.com' },
  emailNormalized: { S: 'ada@example.com' },
  emailVerified: { BOOL: true },
  name: { NULL: true },
  sessionVersion: { N: '0' },
  lastMailAt: { N: '0' },
  wrongCodes: { N: '0' },
  createdAt: { N: '1' },
};

describe('DynamoDB adapter', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('writes a record with its unique values and index entries in one transaction', async () => {
    const { client, sent } = scriptedClient([{}, {}]);
    const store = createDynamoDbAdapter({ tableName: 'madauth', client });

    expect(await store.create('user', user)).toBe(true);
    await store.create('account', { id: 'acc_1', userId: 'usr_1', key: 'password:usr_1', secret: null, failedAttempts: 0, lockedUntil: 0, createdAt: 1 });

    expect(sent.map((s) => s.command)).toEqual(['TransactWriteItemsCommand', 'TransactWriteItemsCommand']);
    expect(sent[0].input.TransactItems).toEqual([
      { Put: { TableName: 'madauth', Item: userItem, ConditionExpression: 'attribute_not_exists(pk)' } },
      {
        Put: {
          TableName: 'madauth',
          Item: { pk: { S: 'u|user|emailNormalized|ada@example.com' }, sk: { S: '#' }, ref: { S: 'usr_1' } },
          ConditionExpression: 'attribute_not_exists(pk)',
        },
      },
    ]);
    expect(sent[1].input.TransactItems.map((item: any) => item.Put.Item.pk.S + ' ' + item.Put.Item.sk.S)).toEqual([
      'r|account|acc_1 #',
      'i|account|userId|usr_1 acc_1',
      'u|account|key|password:usr_1 #',
    ]);
    expect(sent[1].input.TransactItems[1].Put.ConditionExpression).toBeUndefined();
    expect(sent[1].input.TransactItems[2].Put).toMatchObject({ Item: { ref: { S: 'acc_1' } }, ConditionExpression: 'attribute_not_exists(pk)' });
  });

  it('reads with strong consistency and returns only the schema fields', async () => {
    const { client, sent } = scriptedClient([{ Item: { ref: { S: 'usr_1' } } }, { Item: userItem }]);
    const store = createDynamoDbAdapter({ tableName: 'madauth', client });

    expect(await store.findOne('user', { emailNormalized: 'ada@example.com' })).toEqual(user);

    expect(sent).toEqual([
      { command: 'GetItemCommand', input: { TableName: 'madauth', Key: { pk: { S: 'u|user|emailNormalized|ada@example.com' }, sk: { S: '#' } }, ConsistentRead: true } },
      { command: 'GetItemCommand', input: { TableName: 'madauth', Key: { pk: { S: 'r|user|usr_1' }, sk: { S: '#' } }, ConsistentRead: true } },
    ]);
  });

  it('a duplicate is refused without trying again', async () => {
    const { client, sent } = scriptedClient([awsError('TransactionCanceledException', ['None', 'ConditionalCheckFailed'])]);
    const store = createDynamoDbAdapter({ tableName: 'madauth', client });

    expect(await store.create('user', user)).toBe(false);
    expect(sent.length).toBe(1);
  });

  it('sends a transaction again when another write was in its way', async () => {
    vi.spyOn(Math, 'random').mockReturnValue(0);
    const { client, sent } = scriptedClient([
      awsError('TransactionCanceledException', ['TransactionConflict', 'None']),
      awsError('TransactionInProgressException'),
      {},
    ]);
    const store = createDynamoDbAdapter({ tableName: 'madauth', client });

    expect(await store.create('user', user)).toBe(true);
    expect(sent.length).toBe(3);
  });

  it('a delete that lost against another one counts 0, also after a conflict', async () => {
    vi.spyOn(Math, 'random').mockReturnValue(0);
    const { client, sent } = scriptedClient([
      { Item: userItem },
      awsError('TransactionCanceledException', ['TransactionConflict', 'None']),
      awsError('TransactionCanceledException', ['ConditionalCheckFailed', 'None']),
    ]);
    const store = createDynamoDbAdapter({ tableName: 'madauth', client });

    expect(await store.delete('user', { id: 'usr_1' })).toBe(0);
    expect(sent.map((s) => s.command)).toEqual(['GetItemCommand', 'TransactWriteItemsCommand', 'TransactWriteItemsCommand']);
    expect(sent[2].input.TransactItems.map((item: any) => item.Delete.Key.pk.S)).toEqual([
      'r|user|usr_1',
      'u|user|emailNormalized|ada@example.com',
    ]);
  });

  it('an update whose filter no longer matches counts 0, and a clash with a transaction is tried again', async () => {
    vi.spyOn(Math, 'random').mockReturnValue(0);
    const { client, sent } = scriptedClient([
      awsError('TransactionCanceledException', ['TransactionConflict']),
      awsError('TransactionCanceledException', ['ConditionalCheckFailed']),
    ]);
    const store = createDynamoDbAdapter({ tableName: 'madauth', client });

    expect(await store.update('user', { id: 'usr_1', sessionVersion: 0 }, { name: 'Ada', sessionVersion: 1 })).toBe(0);

    // With the id in the filter, the update's condition decides without reading the record first.
    expect(sent.map((s) => s.command)).toEqual(['TransactWriteItemsCommand', 'TransactWriteItemsCommand']);
    // Field names only appear as placeholders: `name` is a reserved word in DynamoDB.
    expect(sent[0].input.TransactItems[0].Update).toMatchObject({
      Key: { pk: { S: 'r|user|usr_1' }, sk: { S: '#' } },
      UpdateExpression: 'SET #p0 = :p0, #p1 = :p1',
      ConditionExpression: 'attribute_exists(pk) AND #w0 = :w0 AND #w1 = :w1',
      ExpressionAttributeNames: { '#w0': 'id', '#w1': 'sessionVersion', '#p0': 'name', '#p1': 'sessionVersion' },
      ExpressionAttributeValues: { ':w0': { S: 'usr_1' }, ':w1': { N: '0' }, ':p0': { S: 'Ada' }, ':p1': { N: '1' } },
    });
  });

  it('gives up when the conflicts do not end, and passes other errors on', async () => {
    vi.spyOn(Math, 'random').mockReturnValue(0);
    const conflict = awsError('TransactionCanceledException', ['TransactionConflict']);
    const busy = scriptedClient(Array.from({ length: 20 }, () => conflict));
    await expect(createDynamoDbAdapter({ tableName: 'madauth', client: busy.client }).create('user', user)).rejects.toBe(conflict);
    expect(busy.sent.length).toBe(9);

    const missing = scriptedClient([awsError('ResourceNotFoundException')]);
    await expect(createDynamoDbAdapter({ tableName: 'nope', client: missing.client }).create('user', user)).rejects.toThrow(
      'ResourceNotFoundException',
    );
    const invalid = scriptedClient([awsError('TransactionCanceledException', ['ValidationError'])]);
    await expect(createDynamoDbAdapter({ tableName: 'madauth', client: invalid.client }).create('user', user)).rejects.toThrow(
      'TransactionCanceledException',
    );
  });

  it('never scans the table: a filter needs the id, a unique field or an indexed field', async () => {
    const { client, sent } = scriptedClient([]);
    const store = createDynamoDbAdapter({ tableName: 'madauth', client });

    await expect(store.findMany('user', { emailVerified: true })).rejects.toThrow(/can't find "user" records by emailVerified/);
    await expect(store.delete('verification', {})).rejects.toThrow(/by nothing/);
    await expect(store.findOne('account', { userId: null })).rejects.toThrow(/needs the id, a unique field or an indexed field/);
    expect(sent).toEqual([]);
  });

  it('refuses to change key fields, unknown models and unknown fields', async () => {
    const { client, sent } = scriptedClient([]);
    const store = createDynamoDbAdapter({ tableName: 'madauth', client });

    await expect(store.update('user', { id: 'usr_1' }, { emailNormalized: 'x@example.com' })).rejects.toThrow(/can't change "emailNormalized"/);
    await expect(store.update('account', { id: 'acc_1' }, { userId: 'usr_2' })).rejects.toThrow(/can't change "userId"/);
    await expect(store.findOne('nope', { id: 'x' })).rejects.toThrow(/Unknown model/);
    await expect(store.findOne('user', { nope: 1 })).rejects.toThrow(/Unknown field/);
    await expect(store.create('user', { ...user, nope: 1 })).rejects.toThrow(/Unknown field/);
    expect(await store.update('user', { id: 'usr_1' }, {})).toBe(0);
    expect(sent).toEqual([]);
  });

  it('is built only on the public API and loads the AWS SDK on first use', () => {
    const source = readFileSync(new URL('./dynamodb.ts', import.meta.url), 'utf8');
    const imports = [...source.matchAll(/^import .* from '([^']+)'/gm)].map((m) => m[1]);

    expect(imports.sort()).toEqual(['./schema.js', '@aws-sdk/client-dynamodb']);
    expect(source).toMatch(/import type \{[^}]*\} from '@aws-sdk\/client-dynamodb'/);
  });
});
