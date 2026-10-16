// Published as `@madauth/server/aws-kms`: the AWS KMS key service, and setting up and rotating its keys (e.g. in the
// AWS template's rotator). It needs the `@aws-sdk/client-kms` package, which AWS Lambda's Node.js runtimes contain.
export { aliasPrefix, createAwsKmsKeyService, deploymentOf, kmsFromSdk, type Kms, type KmsKeyKind } from './aws-kms.js';
export { rotateKmsKeys, serverKmsPolicy, setUpKmsKeys, type RotationOptions } from './kms-rotation.js';
