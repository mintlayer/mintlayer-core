import { useState } from "react";

function Home() {
  const [netMode, setNetMod] = useState("");
  const [walletMode, setWalletMode] = useState("");

  return (
    <div className="home-page">
      {(!netMode || !walletMode) && (
        <div className="banner">
          <div className="container">
            <h1 className="h1 font-bold text-2xl">
              Select {!netMode ? "Network" : !walletMode ? "Wallet Mode" : ""}
            </h1>
            <p>
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
            {" "}
            {/* This creates a vertical layout with space between buttons */}
            <button
              onClick={() => setNetMod("mainnet")}
              className="py-2 px-4 bg-blue-500 text-white rounded w-24"
            >
              Mainnet
            </button>
            <button
              onClick={() => setNetMod("testnet")}
              className="py-2 px-4 bg-blue-500 text-white rounded w-24"
            >
              Testnet
            </button>
          </div>
        ) : !walletMode ? (
          <div className="flex flex-col space-y-2 items-center">
            {" "}
            {/* This creates a vertical layout with space between buttons */}
            <button
              onClick={() => setWalletMode("hot")}
              className="py-2 px-4 bg-blue-500 text-white rounded w-48"
            >
              Hot Wallet
            </button>
            <button
              onClick={() => setWalletMode("cold")}
              className="py-2 px-4 bg-blue-500 text-white rounded w-48"
            >
              Cold Wallet
            </button>
          </div>
        ) : (
          <div className="container"></div>
        )}
      </div>
    </div>
  );
}

export default Home;
