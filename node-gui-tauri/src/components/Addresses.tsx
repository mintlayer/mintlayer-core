import { AiOutlineCopy } from "react-icons/ai";
import AddressIcon from "../assets/account_icon.png";

const Addresses = () => {
  const addresses = [
    "asudfoiuae8u9a8eu9f8ase98fuas9",
    "8euf98weufaosdufjwe8uf0asd9fud",
    "asudfoiuae8u9a8eu9f8ase98fuas9",
  ];
  return (
    <div className="pt-0">
      <p>ADDRESS</p>
      <table className="w-[50vw] border border-gray-200 rounded rounded-lg overflow-hidden shadow">
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
          {addresses.map((address, index) => (
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
