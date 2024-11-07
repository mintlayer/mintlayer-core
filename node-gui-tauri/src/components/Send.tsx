import { useState } from "react";
import { IoCloseSharp } from "react-icons/io5";
import { invoke } from "@tauri-apps/api/core";
const Send = (props: { walletId: number; accountId: number }) => {
  const [address, setAddress] = useState("");
  const [amount, setAmount] = useState("");
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const handleSend = async () => {
    try {
      const transactionInfo = await invoke("send_amount_wrapper", {
        request: {
          wallet_id: props.walletId,
          account_id: props.accountId,
          amount: amount,
          address: address,
        },
      });
      if (transactionInfo) {
        console.log("trasaction info is =========>", transactionInfo);
        setShowConfirmModal(true);
      }
    } catch (error) {}
  };
  return (
    <div className="container mx-auto p-2">
      {showConfirmModal && (
        <div className="bg-white rounded-lg shadow-lg z-10 p-6 max-w-lg mx-auto relative space-y-4">
          <>
            <button
              className="absolute top-2 right-2 text-gray-600 "
              onClick={() => setShowConfirmModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">Transaction Info</h2>
            <p className="mb-4">Your Wallet Mnemonic</p>

            <button
              className="bg-green-400 text-black w-full px-4 py-2 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={() => setShowConfirmModal(false)}
            >
              Confirm
            </button>
          </>
        </div>
      )}
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
          className="py-1 px-4 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black "
        >
          Send
        </button>
      </form>
    </div>
  );
};

export default Send;
