import { toast } from "react-toastify";
import * as blake from 'blakejs';
import {bech32m} from 'bech32';

export const encodeToHash = (data: string)=>{
  const hash = blake.blake2bHex(data, undefined ,32);
  console.log('hash value is===>', hash)
  return hash;
}

export const encode = (prefix: string, data: ArrayLike<number>)=>{
  let address = bech32m.encode(prefix, data);
  return address;
}

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