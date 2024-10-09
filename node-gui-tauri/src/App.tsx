// import { useState } from "react";
import { BrowserRouter as Router, Routes, Route, Link } from "react-router-dom";
import Home from "./pages/Home";

import { invoke } from "@tauri-apps/api/core";
import "./App.css";

function App() {
  return (
    <Router>
      <header></header>
      <main>
        <Routes>
          <Route path="/" element={<Home />} />
        </Routes>
      </main>
      <footer></footer>
    </Router>
  );
}

export default App;
