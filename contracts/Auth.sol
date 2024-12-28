// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./MyStringLibrary.sol";

contract Auth {
    using MyStringLibrary for string;

    struct User {
        string login;
        bytes password;
    }

    address owner;

    mapping(address => mapping(string => User[])) users;
    mapping(address => string[]) sites;
    mapping(address => string[]) usersSites;
    mapping(string => bool) siteExist;

    event NewUser(string site, string login, bytes password);
    event ChangeSite(string oldSiteName, string newSiteName);
    event ChangeLogin(string site, string oldLogin, string newLogin);
    event ChangePassword(string site, string login, bytes newPassword);
    event DeleteSite(string site);
    event DeleteAccount(string site, string login);

    modifier isAuth(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) {
        require(
            msg.sender == verifySignature(message, v, r, s),
            "You cannot change someone else's state"
        );
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function verifySignature(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        bytes32 signature = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", message)
        );
        address signer = ecrecover(signature, v, r, s);
        return signer;
    }

    function changeSiteName(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s,
        string memory oldSiteName,
        string memory newSiteName
    ) external isAuth(message, v, r, s) {
        require(siteExist[oldSiteName], "Site with this name does not exist");

        // Move users to new site name
        users[msg.sender][newSiteName] = users[msg.sender][oldSiteName];
        delete users[msg.sender][oldSiteName];

        // Update site mappings
        for (uint i = 0; i < sites[msg.sender].length; i++) {
            if (sites[msg.sender][i].isEqual(oldSiteName)) {
                sites[msg.sender][i] = newSiteName;
                break;
            }
        }

        for (uint i = 0; i < usersSites[msg.sender].length; i++) {
            if (usersSites[msg.sender][i].isEqual(oldSiteName)) {
                usersSites[msg.sender][i] = newSiteName;
                break;
            }
        }

        delete siteExist[oldSiteName];
        siteExist[newSiteName] = true;

        emit ChangeSite(oldSiteName, newSiteName);
    }

    function deleteSiteInfo(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s,
        string memory site
    ) external isAuth(message, v, r, s) {
        require(siteExist[site], "Site with this name does not exist");

        delete users[msg.sender][site];

        for (uint i = 0; i < sites[msg.sender].length; i++) {
            if (sites[msg.sender][i].isEqual(site)) {
                sites[msg.sender][i] = sites[msg.sender][sites[msg.sender].length - 1];
                sites[msg.sender].pop();
                break;
            }
        }

        for (uint i = 0; i < usersSites[msg.sender].length; i++) {
            if (usersSites[msg.sender][i].isEqual(site)) {
                usersSites[msg.sender][i] = usersSites[msg.sender][usersSites[msg.sender].length - 1];
                usersSites[msg.sender].pop();
                break;
            }
        }

        delete siteExist[site];

        emit DeleteSite(site);
    }

    function deleteAccountInfo(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s,
        string memory site,
        string memory login
    ) external isAuth(message, v, r, s) {
        require(siteExist[site], "Site with this name does not exist");

        for (uint i = 0; i < users[msg.sender][site].length; i++) {
            if (users[msg.sender][site][i].login.isEqual(login)) {
                users[msg.sender][site][i] = users[msg.sender][site][users[msg.sender][site].length - 1];
                users[msg.sender][site].pop();
                break;
            }
        }

        emit DeleteAccount(site, login);
    }

    function changeSiteLogin(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s,
        string memory site,
        string memory oldLogin,
        string memory newLogin
    ) external isAuth(message, v, r, s) {
        require(siteExist[site], "Site with this name does not exist");

        for (uint i = 0; i < users[msg.sender][site].length; i++) {
            if (users[msg.sender][site][i].login.isEqual(oldLogin)) {
                users[msg.sender][site][i].login = newLogin;
                break;
            }
        }

        emit ChangeLogin(site, oldLogin, newLogin);
    }

    function changeSitePassword(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s,
        string memory site,
        string memory login,
        bytes memory newPassword
    ) external isAuth(message, v, r, s) {
        require(siteExist[site], "Site with this name does not exist");

        for (uint i = 0; i < users[msg.sender][site].length; i++) {
            if (users[msg.sender][site][i].login.isEqual(login)) {
                users[msg.sender][site][i].password = newPassword;
                break;
            }
        }

        emit ChangePassword(site, login, newPassword);
    }

    function addUserToSite(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s,
        string memory site,
        string memory _login,
        bytes memory _password
    ) external isAuth(message, v, r, s) {
        if (users[msg.sender][site].length == 0) {
            sites[msg.sender].push(site);
        }

        if (!siteExist[site]) {
            siteExist[site] = true;
            usersSites[msg.sender].push(site);
        }

        users[msg.sender][site].push(User(_login, _password));

        emit NewUser(site, _login, _password);
    }

    function getSites(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public view isAuth(message, v, r, s) returns (string[] memory) {
        return sites[msg.sender];
    }

    function getLogins(
        bytes32 message,
        uint8 v,
        bytes32 r,
        bytes32 s,
        string memory site
    ) public view isAuth(message, v, r, s) returns (User[] memory) {
        return users[msg.sender][site];
    }
}
