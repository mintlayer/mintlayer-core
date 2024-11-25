import { useState } from "react";
import { IoCloseSharp } from "react-icons/io5";
import { invoke } from "@tauri-apps/api/core";
import { encodeToHash, notify } from "../utils/util";
import { AccountType, Data } from "../types/Types";
const Send = (props: {
  currentAccount: AccountType | undefined;
  walletId: number;
  accountId: number;
}) => {
  const [address, setAddress] = useState("");
  const [amount, setAmount] = useState("");
  const [transactionInfo, setTransactionInfo] = useState<Data | undefined>();
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const handleSend = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    event.stopPropagation();
    try {
      const transactionResult: Data = await invoke("send_amount_wrapper", {
        request: {
          wallet_id: props.walletId,
          account_id: props.accountId,
          amount: amount,
          address: address,
        },
      });
      if (transactionResult) {
        console.log("trasaction info is =========>", transactionResult);
        setTransactionInfo(transactionResult);
        setShowConfirmModal(true);
      }
    } catch (error) {
      notify(new String(error).toString(), "error");
    }
  };

  const handleConfirmTransaction = async () => {
    try {
      const result = await invoke("submit_transaction_wrapper", {
        request: {
          wallet_id: props.walletId,
          account_id: props.accountId,
          tx: transactionInfo?.tx,
        },
      });
      console.log("sending amount transaction result is ========>", result);
      notify("Transaction confirmed successfully!", "success");
      setShowConfirmModal(false);
    } catch (error) {
      notify(new String(error).toString(), "error");
    }
  };
  return (
    <div className="container mx-auto p-2">
      <style>{`
        /* Hide the spin buttons for WebKit-based browsers */
        input[type="number"]::-webkit-inner-spin-button,
        input[type="number"]::-webkit-outer-spin-button {
          -webkit-appearance: none;
          margin: 0;
        }

        /* Hide the spin buttons for Firefox */
        input[type="number"] {
          -moz-appearance: textfield;
        }

        /* Adjust the position of the clear button */
        .input-container button {
          right: 36px; /* Adjust this value as needed */
        }
      `}</style>

      {showConfirmModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div
            className="bg-white rounded-lg shadow-lg z-10 p-4 max-w-xl mx-auto relative space-y-4"
            style={{ minWidth: "300px", maxWidth: "90%" }}
          >
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowConfirmModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-xl font-bold mb-4">Confirm Transaction</h2>
            <p className="text-start text-lg text-bold">Transaction summary</p>
            <div>
              <p className="text-start text-bold">BEGIN OF INPUTS</p>
              <p className="text-start whitespace-nowrap">
                -Transaction id ({""}
                {encodeToHash(
                  JSON.stringify(transactionInfo?.tx.transaction.V1)
                )}
                )
              </p>
              <p className="text-start whitespace-nowrap">
                -Transaction ({"0x"}
                {
                  transactionInfo?.tx.transaction.V1.inputs[0].Utxo.id
                    .Transaction
                }
                {", "}
                {transactionInfo?.tx.transaction.V1.inputs[0].Utxo.index})
              </p>
            </div>
            <div>
              <p className="text-start  text-bold">END OF INPUTS</p>
            </div>
            <div>
              <p className="text-start">BEGIN OF OUTPUTS</p>
              <p className="text-start whitespace-nowrap">
                -Transfer({address}, {amount}),
              </p>
              <p className="text-start">
                -Transfer({props.currentAccount?.addresses[0]},{" "}
                {props.currentAccount?.balance.coins.atoms
                  ? props.currentAccount.balance.coins.atoms
                  : 0 - parseInt(amount)}
                ),
              </p>
            </div>
            <div>
              <p className="text-start text-bold">END OF OUTPUTS</p>
            </div>
            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={() => {
                handleConfirmTransaction();
                setShowConfirmModal(false);
              }}
            >
              Confirm and Broadcast
            </button>
          </div>
        </div>
      )}
      <form
        onSubmit={(e) => handleSend(e)}
        className="flex flex-col items-center space-y-2"
      >
        <p className="text-lg font-semibold text-start w-80">Address</p>
        <div className="relative">
          <input
            type="text"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="Enter address"
            className="w-80 shadow-md focus:outline-none focus:ring-2 focus:ring-blue-500 border border-gray-300 rounded-lg py-2 px-3"
          />
          <button
            className="absolute inset-y-0 right-0 hover:outline-none text-gray-800 p-2 rounded focus:outline-none shadow-none"
            onClick={(e) => {
              e.preventDefault();
              setAddress("");
            }}
          >
            <IoCloseSharp />
          </button>
        </div>

        <p className="text-lg font-semibold text-start w-80">Amount</p>
        <div className="relative">
          <button
            className="absolute inset-y-0 right-0 hover:outline-none text-gray-800 p-2 rounded focus:outline-none shadow-none"
            onClick={(e) => {
              e.preventDefault();
              setAmount("");
            }}
          >
            <IoCloseSharp />
          </button>
          <input
            type="number"
            value={amount}
            min={0}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="Enter amount"
            className="w-80 shadow-md focus:outline-none focus:ring-2 focus:ring-blue-500 border border-gray-300 rounded-lg py-2 px-3"
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
