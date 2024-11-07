import { AiOutlineCopy } from "react-icons/ai";
import { invoke } from "@tauri-apps/api/core";
import AddressIcon from "../assets/account_icon.png";
import { notify } from "../utils/util";

const Addresses = (props: {
  addresses: Record<string, string>;
  accountId: number;
  walletId: number;
}) => {
  const handleAddAddress = async () => {
    try {
      const addressInfo = await invoke("new_address_wrapper", {
        request: { wallet_id: props.walletId, account_id: props.accountId },
      });
      if (addressInfo) {
        console.log("new address info is======>", addressInfo);
      }
    } catch (err: any) {
      const regex = /Wallet error: (.+)/;
      const errorMessage = new String(err).match(regex);
      if (errorMessage) {
        notify(errorMessage[1], "error");
      }
      console.log(err);
    }
  };
  return (
    <div className="pt-0">
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
