import _binary from 'bops'
import { BundleItem } from "./BundleItem";
import base64url from "base64url";

const ARWEAVE_CONFIG = {
  sigLength: 512,
  pubLength: 512,
  sigName: "arweave",
}

const MIN_BINARY_SIZE = 80

export default class DataItem implements BundleItem {
  private readonly binary: Uint8Array;
  private _id: Uint8Array;

  constructor(binary: Uint8Array) {
    this.binary = binary;
  }

  static isDataItem(obj: any): obj is DataItem {
    return obj.binary !== undefined;
  }

  get signatureType(): number {
    const ARWEAVE = 1
    const signatureTypeVal: number = byteArrayToLong(
      this.binary.subarray(0, 2),
    );

    switch (signatureTypeVal) {
      case 1: {
        return ARWEAVE;
      }

      default: {
        throw new Error("Unknown signature type: " + signatureTypeVal);
      }
    }
  }

  async isValid(): Promise<boolean> {
    return DataItem.verify(this.binary);
  }

  get id(): string {
    return base64url.encode(this.rawId);
  }

  set id(id: string) {
    this._id = base64url.toBuffer(id);
  }

  get rawId(): Uint8Array {
    return crypto.createHash("sha256").update(this.rawSignature).digest();
  }

  set rawId(id: Uint8Array) {
    this._id = id;
  }

  get rawSignature(): Uint8Array {
    return this.binary.subarray(2, 2 + this.signatureLength);
  }

  get signature(): string {
    return base64url.encode(this.rawSignature);
  }

  set rawOwner(pubkey: Uint8Array) {
    if (pubkey.byteLength != this.ownerLength) throw new Error(`Expected raw owner (pubkey) to be ${this.ownerLength} bytes, got ${pubkey.byteLength} bytes.`);
    this.binary.set(pubkey, 2 + this.signatureLength);
  }

  get signatureLength(): number {
    return ARWEAVE_CONFIG.sigLength;
  }

  get rawOwner(): Uint8Array {
    return this.binary.subarray(
      2 + this.signatureLength,
      2 + this.signatureLength + this.ownerLength,
    );
  }

  get owner(): string {
    return base64url.encode(this.rawOwner);
  }

  get ownerLength(): number {
    return ARWEAVE_CONFIG.pubLength;
  }

  get rawTarget(): Uint8Array {
    const targetStart = this.getTargetStart();
    const isPresent = this.binary[targetStart] == 1;
    return isPresent
      ? this.binary.subarray(targetStart + 1, targetStart + 33)
      : Buffer.alloc(0);
  }

  get target(): string {
    return base64url.encode(this.rawTarget);
  }

  get rawAnchor(): Uint8Array {
    const anchorStart = this.getAnchorStart();
    const isPresent = this.binary[anchorStart] == 1;

    return isPresent
      ? this.binary.subarray(anchorStart + 1, anchorStart + 33)
      : Buffer.alloc(0);
  }

  get anchor(): string {
    return this.rawAnchor.toString();
  }

  get rawTags(): Uint8Array {
    const tagsStart = this.getTagsStart();
    const tagsSize = byteArrayToLong(
      this.binary.subarray(tagsStart + 8, tagsStart + 16),
    );
    return this.binary.subarray(tagsStart + 16, tagsStart + 16 + tagsSize);
  }

  get tags(): { name: string; value: string; }[] {
    const tagsStart = this.getTagsStart();
    const tagsCount = byteArrayToLong(
      this.binary.subarray(tagsStart, tagsStart + 8),
    );
    if (tagsCount == 0) {
      return [];
    }

    const tagsSize = byteArrayToLong(
      this.binary.subarray(tagsStart + 8, tagsStart + 16),
    );

    return tagsParser.fromBuffer(
      _binary.from(
        this.binary.subarray(tagsStart + 16, tagsStart + 16 + tagsSize),
      ),
    );
  }

  get tagsB64Url(): { name: string; value: string; }[] {
    const _tags = this.tags;
    return _tags.map((t) => ({
      name: base64url.encode(t.name),
      value: base64url.encode(t.value),
    }));
  }

  getStartOfData(): number {
    const tagsStart = this.getTagsStart();

    const numberOfTagBytesArray = this.binary.subarray(
      tagsStart + 8,
      tagsStart + 16,
    );
    const numberOfTagBytes = byteArrayToLong(numberOfTagBytesArray);
    return tagsStart + 16 + numberOfTagBytes;
  }

  get rawData(): Uint8Array {
    const tagsStart = this.getTagsStart();

    const numberOfTagBytesArray = this.binary.subarray(
      tagsStart + 8,
      tagsStart + 16,
    );
    const numberOfTagBytes = byteArrayToLong(numberOfTagBytesArray);
    const dataStart = tagsStart + 16 + numberOfTagBytes;

    return this.binary.subarray(dataStart, this.binary.length);
  }

  get data(): string {
    return base64url.encode(this.rawData);
  }

  /**
   * UNSAFE!!
   * DO NOT MUTATE THE BINARY ARRAY. THIS WILL CAUSE UNDEFINED BEHAVIOUR.
   */
  getRaw(): Uint8Array {
    return this.binary;
  }

  public async sign(): Promise<Uint8Array> {
    // need arweaveWallet signer
    this._id = await sign(this, signer);
    return this.rawId;
  }

  public async setSignature(signature: Uint8Array): Promise<void> {
    this.binary.set(signature, 2);
    this._id = _binary.from(await Arweave.crypto.hash(signature));
  }

  public isSigned(): boolean {
    return (this._id?.length ?? 0) > 0;
  }

  /**
   * Returns a JSON representation of a DataItem
   */
  public toJSON(): {
    owner: string;
    data: string;
    signature: string;
    target: string;
    tags: { name: string; value: string; }[];
  } {
    return {
      signature: this.signature,
      owner: this.owner,
      target: this.target,
      tags: this.tags.map((t) => ({
        name: base64url.encode(t.name),
        value: base64url.encode(t.value),
      })),
      data: this.data,
    };
  }


  /**
   * Verifies a `binary` and checks it fits the format of a DataItem
   *
   * A binary is valid iff:
   * - the tags are encoded correctly
   */
  static async verify(buffer: Uint8Array): Promise<boolean> {
    if (buffer.byteLength < MIN_BINARY_SIZE) {
      return false;
    }
    const item = new DataItem(buffer);
    const sigType = item.signatureType;
    const tagsStart = item.getTagsStart();

    const numberOfTags = byteArrayToLong(
      buffer.subarray(tagsStart, tagsStart + 8),
    );
    const numberOfTagBytesArray = buffer.subarray(
      tagsStart + 8,
      tagsStart + 16,
    );
    const numberOfTagBytes = byteArrayToLong(numberOfTagBytesArray);

    if (numberOfTagBytes > 4096) return false;

    if (numberOfTags > 0) {
      try {
        const tags: { name: string; value: string; }[] = tagsParser.fromBuffer(
          _binary.from(
            binary.subarray(tagsStart + 16, tagsStart + 16 + numberOfTagBytes),
          ),
        );

        if (tags.length !== numberOfTags) {
          return false;
        }
      } catch (e) {
        return false;
      }
    }

    // eslint-disable-next-line @typescript-eslint/naming-convention
    const Signer = indexToType[sigType];

    const signatureData = await getSignatureData(item);
    return await Signer.verify(item.rawOwner, signatureData, item.rawSignature);
  }

  public async getSignatureData(): Promise<Uint8Array> {
    return getSignatureData(this);
  }

  /**
   * Returns the start byte of the tags section (number of tags)
   *
   * @private
   */
  private getTagsStart(): number {
    const targetStart = this.getTargetStart();
    const targetPresent = this.binary[targetStart] == 1;
    let tagsStart = targetStart + (targetPresent ? 33 : 1);
    const anchorPresent = this.binary[tagsStart] == 1;
    tagsStart += anchorPresent ? 33 : 1;

    return tagsStart;
  }

  /**
   * Returns the start byte of the tags section (number of tags)
   *
   * @private
   */
  private getTargetStart(): number {
    return 2 + this.signatureLength + this.ownerLength;
  }

  /**
   * Returns the start byte of the tags section (number of tags)
   *
   * @private
   */
  private getAnchorStart(): number {
    let anchorStart = this.getTargetStart() + 1;
    const targetPresent = this.binary[this.getTargetStart()] == 1;
    anchorStart += targetPresent ? 32 : 0;

    return anchorStart;
  }
}

// utils
function byteArrayToLong(byteArray: Uint8Array): number {
  let value = 0;
  for (let i = byteArray.length - 1; i >= 0; i--) {
    value = value * 256 + byteArray[i];
  }
  return value;
}