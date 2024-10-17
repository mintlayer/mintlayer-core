import { useState } from "react";
import { IoCloseSharp } from "react-icons/io5";
const Send = () => {
  const [address, setAddress] = useState("");
  const [amount, setAmount] = useState("");
  const handleSend = () => {};
  return (
    <div className="container mx-auto p-2">
      <form
        onSubmit={handleSend}
        className="flex flex-col items-center space-y-2"
      >
        <p className="text-lg font-semibold text-left w-60">Address</p>
        <div className="relative">
          <input
            type="text"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="Enter address"
            className="w-60 shadow-md focus:outline-none focus:ring-2 focus:ring-blue-500 border border-gray-300 rounded-lg py-2 px-3"
          />
          <button
            className="absolute inset-y-0 right-0 hover:outline-none text-gray-800 p-2 rounded focus:outline-none"
            onClick={() => setAddress("")}
          >
            <IoCloseSharp />
          </button>
        </div>

        <p className="text-lg font-semibold text-left w-60">Amount</p>
        <div className="relative">
          <button
            className="absolute inset-y-0 right-0 hover:outline-none text-gray-800 p-2 rounded focus:outline-none"
            onClick={() => setAmount("")}
          >
            <IoCloseSharp />
          </button>
          <input
            type="number"
            value={amount}
            min={0}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="Enter amount"
            className="w-60 shadow-md focus:outline-none focus:ring-2 focus:ring-blue-500 border border-gray-300 rounded-lg py-2 px-3"
          />
        </div>

        <button
          type="submit"
          className="w-20 bg-[#50d71e] text-white rounded-lg py-1 hover:bg-blue-600 transition duration-200"
        >
          Send
        </button>
      </form>
    </div>
  );
};

export default Send;
