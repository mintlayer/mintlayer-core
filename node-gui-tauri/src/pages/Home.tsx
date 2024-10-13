import { useState } from "react";
import MintlayerIcon from "../assets/mintlayer_icon.png";
import { BsChevronDown, BsChevronUp } from "react-icons/bs";

function Home() {
  const [netMode, setNetMod] = useState("");
  const [walletMode, setWalletMode] = useState("");
  const [isWalletMenuVisible, setIsWalletMenuVisible] = useState(false);
  const toggleWalletVisible = () => {
    setIsWalletMenuVisible((walletVisible) => !walletVisible);
  };
  const createNewWallet = (mode: string) => {};

  const recoverWallet = (mode: string) => {};

  const openWallet = (mode: string) => {};

  const exit = () => {};

  return (
    <div className="home-page">
      {(!netMode || !walletMode) && (
        <div className="banner">
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
              className="py-2 px-4 bg-blue-500 text-white rounded w-24 bg-[#50d71e] hover:bg-black text-[#000000] font-bold hover:text-[#50d71e]"
            >
              Mainnet
            </button>
            <button
              onClick={() => setNetMod("Testnet")}
              className="py-2 px-4 bg-blue-500 text-white rounded w-24 bg-[#50d71e] hover:bg-black  text-[#000000] font-bold hover:text-[#50d71e]"
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
              className="py-2 px-4 bg-blue-500 text-white rounded w-24 bg-[#50d71e] hover:bg-black text-[#000000] font-bold hover:text-[#50d71e]"
            >
              Hot
            </button>
            <button
              onClick={() => setWalletMode("Cold")}
              className="py-2 px-4 bg-blue-500 text-white rounded w-24 bg-[#50d71e] hover:bg-black text-[#000000] font-bold hover:text-[#50d71e]"
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
                  <button
                    onClick={toggleWalletVisible}
                    className="mb-4 py-2 px-2 bg-[#F3F4F6] text-[#000000] rounded hover:bg-gray-200  w-full text-left items-center flex justify-between translation shadow-none border-none w-full"
                  >
                    <span>Menu</span>
                    {isWalletMenuVisible ? <BsChevronDown /> : <BsChevronUp />}
                  </button>
                  {isWalletMenuVisible && (
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
                  )}
                </div>
              </div>
              <div className="col-span-9 h-full">
                {" "}
                {/* This will take 10/12 of the width */}
                <div className="bg-[#F3F4F6] h-full">
                  {" "}
                  {/* Main content area */}
                  {/* Main content goes here */}
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
