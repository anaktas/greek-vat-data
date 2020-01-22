## Get details for Greek VAT codes
A nodejs [express](https://expressjs.com/) rest API application that obtains the details associated with
a Greek VAT number. The web service provided by the Greek
Public Revenue Authority and the General Secretariat of Information
Systems (GSIS) at the Greek Ministry of Finance is called.

### Installation and setup

First, install [nodejs](https://nodejs.org/en/).

Clone the repo `https://github.com/dspinellis/greek-vat-data` and move to the `js` directory using

```
git clone https://github.com/dspinellis/greek-vat-data.git
cd greek-vat-data/js
```

To start a nodejs webApp that provides REST access to the GSIS Soap service, type

```
npm install
npm start
```

to install nodejs dependencies and start locally a webApp: `http://localhost:3000`.

The webApp provides two main HTTP GET endpoints

1. http://localhost:3000/version
2. http://localhost:3000/details?username=YOUR_USERNAME&password=YOUR_PASSWORD&vatBy=REQUESTER_VAT&vatFor=QUERY_VAT

### Acknowledgements

This project is based on https://github.com/lukelarsen/generator-node-express
