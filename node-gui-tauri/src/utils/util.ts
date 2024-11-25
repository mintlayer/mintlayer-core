import { toast } from "react-toastify";
import * as blake from 'blakejs';
import {bech32m} from 'bech32';

export const encodeToHash = (data: string)=>{
  const hash = blake.blake2bHex(data, undefined ,32);
  console.log('hash value is===>', hash)
  return hash;
}

export const encode = (prefix: string, data: ArrayLike<number>) => {
  // Convert data into a 5-bit word representation
  const words = convertTo5BitWords(data);
  let address = bech32m.encode(prefix, words);
  return address;
}


export const encodeToBytesForAddress = (data: string)=>{
  const hexString = data.match(/{(.*?)}/);  
  if (hexString && hexString[1]) {
    const content = hexString[1];
    
    // Convert the hex string to a byte array
    const byteArray = new Uint8Array(content.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []);
    return byteArray;
  } else {
    return new Uint8Array();
  }
}

const convertTo5BitWords = (data: ArrayLike<number>): number[] => {
  const words: number[] = [];
  let bitAccumulator = 0;
  let bitCount = 0;

  // Convert ArrayLike to an array
  const byteArray = Array.from(data); // or you can use [...data] if data is iterable

  for (let byte of byteArray) {
    bitAccumulator = (bitAccumulator << 8) | byte;
    bitCount += 8;

    while (bitCount >= 5) {
      words.push((bitAccumulator & 0x1f)); // Get the last 5 bits
      bitAccumulator >>= 5; // Shift right by 5 bits
      bitCount -= 5;
    }
  }

  if (bitCount > 0) {
    // If there are leftover bits, push them as well
    words.push((bitAccumulator << (5 - bitCount)) & 0x1f);
  }

  return words;
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