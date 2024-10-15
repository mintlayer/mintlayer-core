// import { useState } from "react";
import { BrowserRouter as Router, Routes, Route, } from "react-router-dom";
import Home from "./pages/Home";

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
