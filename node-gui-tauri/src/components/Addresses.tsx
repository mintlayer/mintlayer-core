import { AiOutlineCopy } from "react-icons/ai";
import { invoke } from "@tauri-apps/api/core";
import AddressIcon from "../assets/account_icon.png";
import { notify } from "../utils/util";
import { AddressInfo } from "../types/Types";
import { useState } from "react";

const Addresses = (props: {
  addresses: Record<string, string>;
  accountId: number;
  walletId: number;
  handleUpdateCurrentAccount: (index: string, address: string) => void;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const handleAddAddress = async () => {
    try {
      setIsLoading(true);
      const addressInfo: AddressInfo = await invoke("new_address_wrapper", {
        request: { wallet_id: props.walletId, account_id: props.accountId },
      });
      if (addressInfo) {
        console.log("new address info is======>", addressInfo);
        props.handleUpdateCurrentAccount(
          addressInfo.index.toString(),
          addressInfo.address
        );
        notify("New address added", "success");
      }
      setIsLoading(false);
    } catch (err: any) {
      const regex = /Wallet error: (.+)/;
      const errorMessage = new String(err).match(regex);
      if (errorMessage) {
        notify(errorMessage[1], "error");
      }
      setIsLoading(false);
      console.log(err);
    }
  };
  return (
    <div className="pt-0">
      {isLoading && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-opacity-50 z-10 p-6 max-w-lg mx-auto relative space-y-4">
            <div className="loader px-10">Adding new address. Please wait.</div>
          </div>
        </div>
      )}
      <table className="w-full border border-gray-200 rounded rounded-lg overflow-hidden shadow">
        <thead className="bg-gray-100 ">
          <tr>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold "></th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              ADDRESS
            </th>

            <th className="py-3 px-4 text-center text-gray-600 font-semibold"></th>
          </tr>
        </thead>
        <tbody>
          {Object.values(props.addresses).map((address, index) => (
            <tr
              key={index}
              className="hover:bg-gray-50 transition duration-200"
            >
              <td className="py-2 px-4 border-b border-gray-200">{index}</td>
              <td className="py-2 px-4 border-b border-gray-200">{address}</td>
              <td className="py-2 px-4 border-b border-gray-200">
                <button
                  onClick={() => navigator.clipboard.writeText(address)}
                  className="flex items-center justify-center p-0 bg-transparent border-none shadow-none focus:outline-none"
                >
                  <AiOutlineCopy />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <button
        onClick={handleAddAddress}
        className="absolute bottom-8 mb-4 py-1 px-2 w-40 text-[#000000] rounded-lg bg-[#69EE96] text-center items-center flex justify-center translation shadow-none border-none "
      >
        <img src={AddressIcon} alt="address_icon" className="pr-2" />
        New Address
      </button>
    </div>
  );
};

export default Addresses;
