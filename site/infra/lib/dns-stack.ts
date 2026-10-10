import { CfnOutput, Fn, Stack, type StackProps } from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import type { Construct } from 'constructs';

export interface DnsProps extends StackProps {
  readonly domain: string;
}

/**
 * The domain's hosted zone. Deploy it first, then set its name servers (the output) at the domain's registrar:
 * the certificate can only be validated once the zone answers for the domain.
 */
export class ZoneStack extends Stack {
  readonly zone: route53.PublicHostedZone;

  constructor(scope: Construct, id: string, props: DnsProps) {
    super(scope, id, props);
    this.zone = new route53.PublicHostedZone(this, 'Zone', { zoneName: props.domain });
    new CfnOutput(this, 'NameServers', {
      value: Fn.join(' ', this.zone.hostedZoneNameServers!),
      description: `Set these as the name servers of ${props.domain} at the registrar`,
    });
  }
}

export interface CertificateProps extends DnsProps {
  readonly zone: route53.IHostedZone;
}

/** The TLS certificate for CloudFront, which must be in us-east-1. */
export class CertificateStack extends Stack {
  readonly certificate: acm.Certificate;

  constructor(scope: Construct, id: string, props: CertificateProps) {
    super(scope, id, props);
    this.certificate = new acm.Certificate(this, 'Certificate', {
      domainName: props.domain,
      subjectAlternativeNames: [`www.${props.domain}`],
      validation: acm.CertificateValidation.fromDns(props.zone),
    });
  }
}
