import { useState } from "react";
import Addresses from "./Addresses";
import Console from "./Console";
import Delegation from "./Delegation";
import Send from "./Send";
import Staking from "./Staking";
import Transactions from "./Transactions";
import { IoCloseSharp } from "react-icons/io5";
const WalletActions = (props: any) => {
  const [showEncryptWalletModal, setShowEncryptWalletModal] = useState(false);
  const [showNewAccountModal, setShowNewAccountModal] = useState(props.showNewAccountModal);
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [showLock, setShowLock] = useState(false);
  const [accountName, setAccountName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [unLockPassword, setUnLockPassword] = useState("");
  const [error, setError] = useState("");

  const handleConfirmPasswordChange = (confirmPassword: string) => {
    setConfirmPassword(confirmPassword);

    // Validate the confirm password
    if (confirmPassword !== password) {
      setError("Passwords do not match.");
    } else if (confirmPassword.length < 8 || confirmPassword.length > 64) {
      setError("Password must be between 8 and 64 characters.");
    } else {
      setError("");
    }
  };
  const handleEncryptWallet = () => {
    // Encrypt wallet logic
    setShowEncryptWalletModal(false);
    setShowLock(true);
  };

  const handleCreateWallet  = ()=>{
    // Create wallet logic
    setShowNewAccountModal(false);
    // props.onAccountCreated(accountName);
  }

  const handleUnlock = ()=>{
    setShowUnLockModal(false);
  }
  return (
    <div className="min-w-full bg-white border border-gray-200 shadowoverflow-y-auto mt-8 p-8 m-8 rounded rounded-lg shadow">
      {showEncryptWalletModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-4 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowEncryptWalletModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">Encrypt Wallet</h2>
            <input
              placeholder="Enter password"
              type="password"
              className="w-full rounded rounded-lg"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <input
              placeholder="Repeat password"
              type="password"
              className="w-full rounded rounded-lg"
              value={confirmPassword}
              onChange={(e) => handleConfirmPasswordChange(e.target.value)}
            />
            {error && <p className="text-red-500 text-sm mt-1">{error}</p>}
            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={() => handleEncryptWallet()}
            >
              Encrypt Wallet
            </button>
          </div>
        </div>
      )}
      {showNewAccountModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-4 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowEncryptWalletModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">New Account</h2>
            <input
              placeholder="Enter a name"
              type="text"
              className="w-full rounded rounded-lg"
              value={password}
              onChange={(e) => setAccountName(e.target.value)}
            />

            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={() => handleCreateWallet()}
            >
              Create
            </button>
          </div>
        </div>
      )}
      {showNewAccountModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-4 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowEncryptWalletModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">Unlock</h2>
            <input
              placeholder="Enter a name"
              type="password"
              className="w-full rounded rounded-lg"
              value={password}
              onChange={(e) => setUnLockPassword(e.target.value)}
            />

            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={() => handleCreateWallet()}
            >
              Unlock
            </button>
          </div>
        </div>
      )}
      <div className="row flex items-center justify-between pl-8 pr-8 pb-0">
        <div>
          <span className="flex inline-block space-x-2">
            <div className="font-thin">My balance: </div>
            <div className="font-bold">{} ML</div>
          </span>
        </div>
        <div className="space-x-2">
          {showLock && (
            <button className="py-1 px-2 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black ">
              Lock
            </button>
          )}
          <button
            className="py-1 px-2 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black"
            onClick={() => setShowEncryptWalletModal(true)}
          >
            {showLock ? "Disable Wallet Encryption" : "Encrypt Wallet"}
          </button>
          <button className="py-1 px-4 mt-8 mb-8 border text-[#E02424] border-[#E02424] bg-white rounded-lg transition-all duration-200 hover:outline-none hover:bg-[#E02424] hover:text-white hover:border-[#E02424]">
            Close Wallet
          </button>
        </div>
      </div>
      {props.activeTab === "transactions" && <Transactions />}
      {props.activeTab === "addresses" && <Addresses />}
      {props.activeTab === "send" && <Send />}
      {props.activeTab === "staking" && <Staking />}
      {props.activeTab === "delegation" && <Delegation />}
      {props.activeTab === "console" && <Console />}
    </div>
  );
};
export default WalletActions;
