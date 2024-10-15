import { useEffect, useState } from "react";
import * as bip39 from "bip39";
import { Modal, initTWE } from "tw-elements";
import { RiInformation2Line } from "react-icons/ri";
import { PiShareNetworkBold } from "react-icons/pi";

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
  const [activeTab, setActiveTab] = useState("home");
  const [currentTab, setCurrentTab] = useState("summary");
  const [showToolTip, setShowToolTip] = useState(0);
  const [currentAccount, setCurrentAccount] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [showNemonicModal, setShowNemonicModal] = useState(false);

  useEffect(() => {
    initTWE({ Modal });
  }, []);

  const createNewWallet = () => {
    try {
      const newMnemonic = bip39.generateMnemonic();
      console.log(newMnemonic);
      setMnemonic(newMnemonic);
      setShowNemonicModal(true);
    } catch (error) {
      console.error(error);
    }
  };

  const recoverWallet = (mode: string) => {};

  const openWallet = (mode: string) => {};

  const exit = () => {};

  return (
    <div className="home-page ">
      {showNemonicModal && (
        <div
          id="default-modal"
          aria-hidden="true"
          className="hidden overflow-y-auto tabIndex-{-1} overflow-x-hidden fixed top-0 right-0 left-0 z-50 justify-center items-center w-full md:inset-0 h-[calc(100%-1rem)] max-h-full"
        >
          <div className="relative p-4 w-full max-w-2xl max-h-full">
            <div className="relative bg-white rounded-lg shadow dark:bg-gray-700">
              <div className="flex items-center justify-between p-4 md:p-5 border-b rounded-t dark:border-gray-600">
                <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
                  Terms of Service
                </h3>
                <button
                  type="button"
                  className="text-gray-400 bg-transparent hover:bg-gray-200 hover:text-gray-900 rounded-lg text-sm w-8 h-8 ms-auto inline-flex justify-center items-center dark:hover:bg-gray-600 dark:hover:text-white"
                  data-modal-hide="default-modal"
                >
                  <svg
                    className="w-3 h-3"
                    aria-hidden="true"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 14 14"
                  >
                    <path
                      stroke="currentColor"
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"
                    />
                  </svg>
                  <span className="sr-only">Close modal</span>
                </button>
              </div>
              <div className="p-4 md:p-5 space-y-4">
                <p className="text-base leading-relaxed text-gray-500 dark:text-gray-400">
                  With less than a month to go before the European Union enacts
                  new consumer privacy laws for its citizens, companies around
                  the world are updating their terms of service agreements to
                  comply.
                </p>
                <p className="text-base leading-relaxed text-gray-500 dark:text-gray-400">
                  The European Union’s General Data Protection Regulation
                  (G.D.P.R.) goes into effect on May 25 and is meant to ensure a
                  common set of data rights in the European Union. It requires
                  organizations to notify users as soon as possible of high-risk
                  data breaches that could personally affect them.
                </p>
              </div>
              <div className="flex items-center p-4 md:p-5 border-t border-gray-200 rounded-b dark:border-gray-600">
                <button
                  data-modal-hide="default-modal"
                  type="button"
                  className="text-white bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800"
                >
                  I accept
                </button>
                <button
                  data-modal-hide="default-modal"
                  type="button"
                  className="py-2.5 px-5 ms-3 text-sm font-medium text-gray-900 focus:outline-none bg-white rounded-lg border border-gray-200 hover:bg-gray-100 hover:text-blue-700 focus:z-10 focus:ring-4 focus:ring-gray-100 dark:focus:ring-gray-700 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600 dark:hover:text-white dark:hover:bg-gray-700"
                >
                  Decline
                </button>
              </div>
            </div>
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
            <button
              onClick={() => setWalletMode("Hot")}
              onMouseEnter={() => setShowToolTip(1)}
              onMouseLeave={() => setShowToolTip(0)}
              className="py-2 px-4 rounded w-24 bg-[#50d71e] hover:bg-black text-[#000000] font-bold hover:text-[#50d71e]"
            >
              Hot
            </button>
            {showToolTip === 1 && (
              <div className="absolute left-1/2 top-1/2 transform -translate-y-1/2 ml-2 w-72 bg-gray-700 text-white text-center text-sm rounded py-1">
                This is the standard operating mode, where all wallet functions
                are available to you. The wallet will be connected to the
                internet, enabling you to stake and carry out all operations
                smoothly. If you're unsure which option to select, we recommend
                choosing 'Hot' for the best experience.
              </div>
            )}
            <button
              onClick={() => setWalletMode("Cold")}
              onMouseEnter={() => setShowToolTip(2)}
              onMouseLeave={() => setShowToolTip(0)}
              className="py-2 px-4 rounded w-24 bg-[#50d71e] hover:bg-black text-[#000000] font-bold hover:text-[#50d71e]"
            >
              Cold
            </button>
            {showToolTip === 2 && (
              <div className="absolute left-1/2 top-1/2 transform -translate-y-1/2 ml-2 w-72 bg-gray-700 text-white text-center text-sm rounded py-1">
                This mode operates a limited version of the node, providing an
                added layer of security by allowing the wallet to function
                without an internet connection. Please note that while in this
                mode, the wallet will not be able to sync, check balances, or
                create transactions (though it can sign transactions that have
                been imported). Additionally, staking features will be disabled.
              </div>
            )}
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
                        onClick={() => setActiveTab("transactions")}
                        className="mb-4 py-2 px-2 text-[#000000] rounded  w-full text-left items-center flex justify-left translation shadow-none border-none w-full"
                      >
                        <img src={TransactionIcon} className="pr-2" />
                        Transactions
                      </button>
                      <button
                        onClick={() => setActiveTab("addresses")}
                        className="mb-4 py-2 px-2 text-[#000000] rounded  w-full text-left items-center flex justify-left translation shadow-none border-none w-full"
                      >
                        <img src={AddressIcon} className="pr-2" />
                        Addresses
                      </button>
                      <button
                        onClick={() => setActiveTab("send")}
                        className="mb-4 py-2 px-2 text-[#000000] rounded  w-full text-left items-center flex justify-left translation shadow-none border-none w-full"
                      >
                        <img src={SendIcon} className="pr-2" />
                        Send
                      </button>
                      <button
                        onClick={() => setActiveTab("staking")}
                        className="mb-4 py-2 px-2 text-[#000000] rounded  w-full text-left items-center flex justify-left translation shadow-none border-none w-full"
                      >
                        <img src={StakingIcon} className="pr-2" />
                        Staking
                      </button>
                      <button
                        onClick={() => setActiveTab("delegation")}
                        className="mb-4 py-2 px-2 text-[#000000] rounded  w-full text-left items-center flex justify-left translation shadow-none border-none w-full"
                      >
                        <img src={DelegationIcon} className="pr-2" />
                        Delegation
                      </button>
                      <button
                        onClick={() => setActiveTab("console")}
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
