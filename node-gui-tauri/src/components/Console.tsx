import { useState } from "react";
import { AiOutlineCopy } from "react-icons/ai";

import { RiDeleteBinLine } from "react-icons/ri";
import { notify } from "../utils/util";
import { invoke } from "@tauri-apps/api/core";
import { AccountType, ConsoleResultType, WalletInfo } from "../types/Types";

const Console = (props: {
  currentAccount: AccountType | undefined;
  currentAccountId: number;
  currentWallet: WalletInfo | undefined;
}) => {
  const [text, setText] = useState("");
  const [command, setCommand] = useState("");
  const handleDelete = () => {
    setText("");
  };
  const handleCopy = () => {
    navigator.clipboard.writeText(text);
  };

  const handleSendCommand = async () => {
    try {
      const result: ConsoleResultType = await invoke(
        "handle_console_command_wrapper",
        {
          request: {
            wallet_id: parseInt(
              props.currentWallet?.wallet_id
                ? props.currentWallet?.wallet_id
                : "0"
            ),
            account_id: props.currentAccountId,
            command: command,
          },
        }
      );
      if (result) {
        console.log(result);
        setText((text) => text + result.Print);
      }
    } catch (error) {
      console.log(error);
      notify(new String(error).toString(), "error");
    }
  };
  return (
    <div className="container border-1px border-gray-100 space-y-4 pt-1">
      <div className="mt-10 p-4 border border-gray-300 rounded-lg ">
        <div className="flex justify-between items-center">
          <h2 className="text-lg font-bold mb-4">Console</h2>
          <div className="flex items-center">
            <div className="w-px h-6 bg-gray-400 mx-2"></div>
            <div className="flex justify-between items-center space-x-4">
              <button
                onClick={handleCopy}
                className="flex items-center justify-center p-0 bg-transparent border-none shadow-none focus:outline-none"
              >
                <AiOutlineCopy />
              </button>
              <button
                onClick={handleDelete}
                className="flex items-center justify-center p-0 bg-transparent border-none shadow-none focus:outline-none"
              >
                <RiDeleteBinLine />
              </button>
            </div>
          </div>
        </div>
        <textarea
          className="w-full h-32 border border-gray-300 rounded-lg p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={text}
          readOnly
        />
      </div>
      <div className="justify-between flex space-x-4 border border-gray-100">
        <input
          className="rounded rounded-lg border border-gray-100 w-full"
          placeholder="Type here ..."
          value={command}
          onChange={(e) => setCommand(e.target.value)}
        />
        <button
          onClick={handleSendCommand}
          className="w-[5rem] py-1 px-4 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black "
        >
          Send
        </button>
      </div>
    </div>
  );
};

export default Console;
