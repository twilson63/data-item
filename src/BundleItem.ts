type ResolvesTo<T> = T | Promise<T> | ((...args: any[]) => Promise<T>);

export abstract class BundleItem {
  readonly signatureType: ResolvesTo<number>;
  readonly rawSignature: ResolvesTo<Uint8Array>;
  readonly signature: ResolvesTo<string>;
  readonly signatureLength: ResolvesTo<number>;
  readonly rawOwner: ResolvesTo<Uint8Array>;
  readonly owner: ResolvesTo<string>;
  readonly ownerLength: ResolvesTo<number>;
  readonly rawTarget: ResolvesTo<Uint8Array>;
  readonly target: ResolvesTo<string>;
  readonly rawAnchor: ResolvesTo<Uint8Array>;
  readonly anchor: ResolvesTo<string>;
  readonly rawTags: ResolvesTo<Uint8Array>;
  readonly tags: ResolvesTo<{ name: string; value: string }[]>;
  readonly rawData: ResolvesTo<Uint8Array>;
  readonly data: ResolvesTo<string>;
  abstract sign(): Promise<Uint8Array>;
  abstract isValid(): Promise<boolean>;
  static async verify(..._: any[]): Promise<boolean> {
    throw new Error("You must implement `verify`");
  }
}