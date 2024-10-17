import { AiOutlineCopy } from "react-icons/ai";
import AddressIcon from "../assets/account_icon.png";

const Addresses = () => {
  const addresses = [
    "asudfoiuae8u9a8eu9f8ase98fuas9",
    "8euf98weufaosdufjwe8uf0asd9fud",
    "asudfoiuae8u9a8eu9f8ase98fuas9",
  ];
  return (
    <div className="container">
      <p>ADDRESS</p>
      <table className="table-auto border border-gray-200">
        <tbody>
          {addresses.map((address, index) => (
            <tr key={index}>
              <td className="text-black font-bold py-1 px-2 whitespace-nowrap">
                {index}
              </td>
              <td className="text-black font-bold py-1 px-2 whitespace-nowrap">
                {address}
              </td>
              <td className="text-black font-bold py-1 px-2 whitespace-nowrap">
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
        onClick={() => {}}
        className="absolute bottom-8 mb-4 py-1 px-2 w-40 text-[#000000] rounded-lg bg-[#69EE96] text-center items-center flex justify-center translation shadow-none border-none "
      >
        <img src={AddressIcon} alt="address_icon" className="pr-2" />
        New Address
      </button>
    </div>
  );
};

export default Addresses;
