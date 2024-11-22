import { toast } from "react-toastify";
// import * as crypto from 'crypto-js';

// type H256 = Buffer;
// const defaultHashAlgo = 'blake2b';

// export const defaultHash = (data:Buffer|Uint8Array):H256 =>{
//   const hash = crypto.createHash(defaultHashAlgo);
//   hash.update(data);
//   return hash.digest();
// }

// export function hashEncodedTo<T>(value: T, hasher: any):void{
//   const encodedValue = encode(value);
//   hasher.update(encodedValue);
// }

// export function hashEncoded<T>(value:T):H256{
//   const hasher = crypto.createHash(defaultHashAlgo);
//   hashEncodedTo(value, hasher);
//   return hasher.digest();
// }

// function encode<T>(value: T): Buffer {
//   // Convert the value to a Buffer. This is a placeholder implementation.
//   return Buffer.from(JSON.stringify(value));
// }

export   const notify = (message: string, type: string) => {
    console.log("notification is displayed");
    switch (type) {
      case "error":
        toast.error(message);
        break;
      case "info":
        toast.info(message);
        break;
      case "success":
        toast.success(message);
        break;
      default:
        toast.info(message);
    }
  };