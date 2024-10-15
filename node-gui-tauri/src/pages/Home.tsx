import { useEffect, useState } from "react";
import * as bip39 from "bip39";
import { Modal, initTWE } from "tw-elements";
import { RiInformation2Line } from "react-icons/ri";
import { PiShareNetworkBold } from "react-icons/pi";
import { IoCloseSharp } from "react-icons/io5";
import { Tooltip, Button } from "flowbite-react";

import MintlayerIcon from "../assets/mintlayer_icon.png";
import TransactionIcon from "../assets/transaction_icon.png";
import AddressIcon from "../assets/address_icon.png";
import SendIcon from "../assets/send_icon.png";
import StakingIcon from "../assets/staking_icon.png";
import DelegationIcon from "../assets/delegation_icon.png";
import ConsoleIcon from "../assets/console_icon.png";
import WalletIcon from "../assets/wallet_icon.png";
import AccountIcom from "../assets/account_icon.png";
import SummaryTab from "../components/Summary";
import NetworkingTab from "../components/Networking";
import { WalletType } from "../types/Types";
import Transactions from "../components/Transactions";

function Home() {
  const wallets = [
    {
      wallet_id: "mintlayer_wallet",
      address: "19832798ser98qw3r98wer7w3r",
      accounts: [{ account_id: "account0" }, { account_id: "account1" }],
    },
    {
      wallet_id: "testnet_wallet",
      address: "swerweferwe879we87f9we8",
      accounts: [{ account_id: "account0" }, { account_id: "account1" }],
    },
  ];

  const [netMode, setNetMod] = useState("");
  const [walletMode, setWalletMode] = useState("");
  const [currentWallet, setCurrentWallet] = useState<WalletType | undefined>(
    wallets?.[0]
  );
  const [currentTab, setCurrentTab] = useState("summary");
  const [showToolTip, setShowToolTip] = useState(0);
  const [currentAccount, setCurrentAccount] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [showNemonicModal, setShowNemonicModal] = useState(false);
  const [showRecoverWalletModal, setShowRecoverWalletModal] = useState(false);

  useEffect(() => {
    initTWE({ Modal });
  }, []);

  const createNewWallet = () => {
    try {
      // const newMnemonic = bip39.generateMnemonic();
      // console.log(newMnemonic);
      // setMnemonic(newMnemonic);
      setShowNemonicModal(true);
    } catch (error) {
      console.error(error);
    }
  };

  const recoverWallet = (mode: string) => {
    setShowRecoverWalletModal(true);
  };

  const openWallet = (mode: string) => {};

  const exit = () => {};

  return (
    <div className="home-page ">
      {showNemonicModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-6 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 text-gray-600 "
              onClick={() => setShowNemonicModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">
              Create New {walletMode} Wallet
            </h2>
            <p className="mb-4">Your Wallet Mnemonic</p>
            <textarea
              value={mnemonic}
              rows={3}
              contentEditable={false}
              className="w-full shadow-[1px] resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 border border-gray-300 rounded-lg"
            />
            <button
              className="bg-green-400 text-black w-full px-4 py-2 rounded-2 hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={() => setShowNemonicModal(false)}
            >
              Create
            </button>
          </div>
        </div>
      )}
      {showRecoverWalletModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-6 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 text-gray-600 "
              onClick={() => setShowRecoverWalletModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">
              Recover {walletMode} Wallet
            </h2>
            <p className="mb-4">Enter Mnemonic</p>
            <textarea
              value={mnemonic}
              onChange={(e) => setMnemonic(e.target.value)}
              rows={3}
              className="w-full shadow-[1px] resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 border border-gray-300 rounded-lg"
            />
            <button
              className="bg-green-400 text-black w-full px-4 py-2 rounded-2 hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={() => setShowRecoverWalletModal(false)}
            >
              Recover
            </button>
          </div>
        </div>
      )}
      {(!netMode || !walletMode) && (
        <div className="banner py-6 ">
          <div className="container w-[100vw]">
            <img
              src={MintlayerIcon}
              alt="mintlayer"
              className="w-40 self-center mb-8 mt-8"
            />

            <p className="text-2xl font-bold">
              Please choose the{" "}
              {!netMode ? "Network" : !walletMode ? "Wallet Mode" : ""} you want
              to use.
            </p>
          </div>
        </div>
      )}
      <div className="container page">
        {!netMode ? (
          <div className="flex flex-col items-center space-y-2">
            <button
              onClick={() => setNetMod("Mainnet")}
              className="py-2 px-4 rounded w-24 bg-[#50d71e] hover:bg-black text-[#000000] font-bold hover:text-[#50d71e]"
            >
              Mainnet
            </button>
            <button
              onClick={() => setNetMod("Testnet")}
              className="py-2 px-4 rounded w-24 bg-[#50d71e] hover:bg-black text-[#000000] font-bold hover:text-[#50d71e]"
            >
              Testnet
            </button>
          </div>
        ) : !walletMode ? (
          <div className="flex flex-col space-y-2 items-center">
            <Tooltip
              content='This is the normal operating mode where all wallet functions are enabled. The wallet will be connected to the internet, allowing you to stake and perform all operations. If you are unsure which option to choose, select "Hot"'
              placement="left"
            >
              <Button
                onClick={() => setWalletMode("Hot")}
                className="py-1 px-4 rounded w-24 bg-[#50d71e] text-[#000000] font-bold text-xl hover:text-[#50d71e] hover:bg-black text-xl"
              >
                Hot
              </Button>
            </Tooltip>

            <Tooltip
              content="This mode runs a limited version of the node. It allows the wallet to operate without an internet connection for added security. In this mode, the wallet cannot sync, check balances, or create transactions (though it can sign imported transactions). Staking is also disabled."
              placement="right"
            >
              <Button
                onClick={() => setWalletMode("Cold")}
                className="py-1 px-4 rounded w-24 bg-[#50d71e] text-[#000000] font-bold text-xl hover:text-[#50d71e] hover:bg-black text-xl"
              >
                Cold
              </Button>
            </Tooltip>
          </div>
        ) : (
          <div className="fixed top-0 left-0 ">
            <div className="grid grid-cols-12 ">
              <div className="col-span-3">
                <div className="flex flex-col  space-y-4 p-4  rounded h-[100vh] w-full overflow-y-auto">
                  <div className="flex justify-center items-center w-[20vw] ">
                    <img src={MintlayerIcon} alt="sidebar_icon" />
                  </div>

                  <>
                    <button
                      onClick={() => createNewWallet()}
                      className="w-full text-[#000000] rounded  transition border-none shadow-none text-left py-2 px-1"
                    >
                      Create New {walletMode} Wallet
                    </button>
                    <button
                      onClick={() => recoverWallet(walletMode)}
                      className="w-full text-[#000000] rounded  transition border-none shadow-none text-left py-2 px-1"
                    >
                      Recover {walletMode} Wallet
                    </button>
                    <button
                      onClick={() => openWallet(walletMode)}
                      className="w-full text-[#000000] rounded  transition border-none shadow-none text-left py-2 px-1"
                    >
                      Open {walletMode} Wallet
                    </button>
                    <button
                      onClick={() => exit()}
                      className="w-full text-[#ff0000] rounded transition border-none py-2 px-1 shadow-none text-left"
                    >
                      Exit
                    </button>
                    <hr className="my-12 h-[2px] bg-gradient-to-r from-transparent via-neutral-500 to-transparent opacity-25 dark:via-neutral-800" />{" "}
                  </>
                  {wallets.length !== 0 && (
                    <>
                      <div className="relative inline-block flex items-center justify-center">
                        <img src={WalletIcon} alt="wallet_ico" />
                        <select
                          defaultValue={
                            wallets.length > 0 ? wallets[0].wallet_id : ""
                          }
                          value={currentWallet?.wallet_id}
                          onClick={(e) =>
                            setCurrentWallet(
                              wallets.find(
                                (wallet) => wallet.wallet_id === e?.target.value
                              )
                            )
                          }
                          className="block w-[16vw] bg-white px-2 border-gray-300 text-gray-700 py-2  rounded-lg shadow-sm focus:outline-none  "
                        >
                          {wallets.map((wallet) => (
                            <option
                              key={wallet.wallet_id}
                              value={wallet.wallet_id}
                            >
                              {wallet.wallet_id}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="relative inline-block pl-4 flex items-center justify-center">
                        <img src={AccountIcom} alt="wallet_ico" />
                        <select
                          defaultValue={
                            wallets.length > 0 ? wallets[0].wallet_id : ""
                          }
                          onClick={(e) => setCurrentAccount(e?.target.value)}
                          value={currentAccount}
                          className="block w-[16vw] bg-white px-2 w-[14vw] border-gray-300 text-gray-700 py-2  rounded-lg shadow-sm focus:outline-none  "
                        >
                          {currentWallet?.accounts.map((account) => (
                            <option
                              key={account.account_id}
                              value={account.account_id}
                            >
                              {account.account_id}
                            </option>
                          ))}
                        </select>
                      </div>
                      <button
                        onClick={() => setCurrentTab("transactions")}
                        className="mb-4 py-2 px-2 text-[#000000] rounded  w-full text-left items-center flex justify-left translation shadow-none border-none w-full"
                      >
                        <img src={TransactionIcon} className="pr-2" />
                        Transactions
                      </button>
                      <button
                        onClick={() => setCurrentTab("addresses")}
                        className="mb-4 py-2 px-2 text-[#000000] rounded  w-full text-left items-center flex justify-left translation shadow-none border-none w-full"
                      >
                        <img src={AddressIcon} className="pr-2" />
                        Addresses
                      </button>
                      <button
                        onClick={() => setCurrentTab("send")}
                        className="mb-4 py-2 px-2 text-[#000000] rounded  w-full text-left items-center flex justify-left translation shadow-none border-none w-full"
                      >
                        <img src={SendIcon} className="pr-2" />
                        Send
                      </button>
                      <button
                        onClick={() => setCurrentTab("staking")}
                        className="mb-4 py-2 px-2 text-[#000000] rounded  w-full text-left items-center flex justify-left translation shadow-none border-none w-full"
                      >
                        <img src={StakingIcon} className="pr-2" />
                        Staking
                      </button>
                      <button
                        onClick={() => setCurrentTab("delegation")}
                        className="mb-4 py-2 px-2 text-[#000000] rounded  w-full text-left items-center flex justify-left translation shadow-none border-none w-full"
                      >
                        <img src={DelegationIcon} className="pr-2" />
                        Delegation
                      </button>
                      <button
                        onClick={() => setCurrentTab("console")}
                        className="mb-4 py-2 px-2 text-[#000000] rounded  w-full text-left items-center flex justify-left translation shadow-none border-none w-full"
                      >
                        <img src={ConsoleIcon} className="pr-2" />
                        Console
                      </button>
                    </>
                  )}
                </div>
              </div>
              <div className="col-span-9 h-full pr-4">
                <div className="bg-[#F3F4F6] h-full w-[74vw]">
                  <div className="flex w-full">
                    <button
                      onClick={() => setCurrentTab("summary")}
                      className={`flex items-center justify-center w-full pl-2  transition-colors duration-300 rounded-tr-[0] rounded-br-[0] ${
                        currentTab === "summary"
                          ? "bg-gray-200 text-gray-800"
                          : "bg-white-500 text-black"
                      }`}
                    >
                      <RiInformation2Line />
                      <span className="pl-2">Summary</span>
                    </button>
                    <button
                      onClick={() => setCurrentTab("network")}
                      className={`flex items-center justify-center w-full p-2 transition-colors duration-300 rounded-tl-[0] rounded-bl-[0] ${
                        currentTab === "network"
                          ? "bg-gray-200 text-gray-800"
                          : "bg-white-500 text-black"
                      }`}
                    >
                      <PiShareNetworkBold />
                      <span className="pl-2">Networking</span>
                    </button>
                  </div>
                  {currentTab === "summary" && <SummaryTab network={netMode} />}
                  {currentTab === "network" && <NetworkingTab />}
                  {currentTab === "transactions" && <Transactions />}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Home;
