/// <reference lib="dom" />

export {};

declare global {
  /** Keep no-type-argument JSON parsing unknown across DOM and Worker types. */
  interface Body {
    json(): Promise<unknown>;
  }
}
