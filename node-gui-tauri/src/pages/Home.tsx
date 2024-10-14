import { useState } from "react";
import { BsChevronDown, BsChevronUp } from "react-icons/bs";
import { RiInformation2Line } from "react-icons/ri";
import { PiShareNetworkBold } from "react-icons/pi";

import MintlayerIcon from "../assets/mintlayer_icon.png";
import TransactionIcon from "../assets/transaction_icon.png";
import AddressIcon from "../assets/address_icon.png";
import SendIcon from "../assets/send_icon.png";
import StakingIcon from "../assets/staking_icon.png";
import DelegationIcon from "../assets/delegation_icon.png";
import ConsoleIcon from "../assets/console_icon.png";
import SummaryTab from "../components/Summary";
import NetworkingTab from "../components/Networking";

function Home() {
  const [netMode, setNetMod] = useState("");
  const [walletMode, setWalletMode] = useState("");
  const [currentWallet, setCurrentWallet] = useState("wallet1");
  const [activeTab, setActiveTab] = useState("home");
  const [currentTab, setCurrentTab] = useState("summary");

  const createNewWallet = (mode: string) => {};

  const recoverWallet = (mode: string) => {};

  const openWallet = (mode: string) => {};

  const exit = () => {};

  return (
    <div className="home-page">
      {(!netMode || !walletMode) && (
        <div className="banner py-6">
          <div className="container">
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
            {" "}
            {/* This creates a vertical layout with space between buttons */}
            <button
              onClick={() => setWalletMode("Hot")}
              className="py-2 px-4 rounded w-24 bg-[#50d71e] hover:bg-black text-[#000000] font-bold hover:text-[#50d71e]"
            >
              Hot
            </button>
            <button
              onClick={() => setWalletMode("Cold")}
              className="py-2 px-4 rounded w-24 bg-[#50d71e] hover:bg-black text-[#000000] font-bold hover:text-[#50d71e]"
            >
              Cold
            </button>
          </div>
        ) : (
          <div className="fixed top-0 left-0">
            <div className="grid grid-cols-12 ">
              <div className="col-span-3 w-full">
                <div className="flex flex-col items-center space-y-4 p-4  rounded h-full w-full">
                  <div className="flex justify-center items-center w-[9rem] px-4">
                    <img src={MintlayerIcon} alt="sidebar_icon" />
                  </div>

                  <>
                    <button
                      onClick={() => createNewWallet(walletMode)}
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
                  </>
                  {currentWallet && (
                    <>
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
              <div className="col-span-9 h-full">
                <div className="bg-[#F3F4F6] h-full w-full">
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
