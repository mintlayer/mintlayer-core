const flowbite = require("flowbite-react/tailwind");
module.exports = {
  content: ["./index.html","./src/**/*.{js,jsx,ts,tsx}", flowbite.content()],
  theme: {
    extend: {},
  },
  plugins: [flowbite.plugin()],
};
