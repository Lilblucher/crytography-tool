# CryptoToolkit Guide

Oct 15, 2026 · @Clive

A hands-on reference for every algorithm in the CryptoToolkit - a Java-based interactive cryptography workbench covering S-DES, RSA, ECC, SHA-256 and MD5. Each tool is covered in two parts: the concept behind it and a practical walkthrough of every menu option.

## S-DES - The Concept

S-DES stands for Simplified Data Encryption Standard. It is a miniature version of a real encryption system called DES, built specifically for learning. Think of DES as a full-size combination safe with 16 locking mechanisms - S-DES is a toy safe with just 2 locking mechanisms. The toy safe uses the exact same design, just small enough that you can take it apart and see how every piece works.

### What does it actually do?

S-DES takes a small piece of data (8 bits - that is one character, like the letter "A") and scrambles it into unreadable gibberish using a secret key (10 bits - just a sequence of ten 0s and 1s). Anyone who has the same key can unscramble it back to the original. It is like a secret decoder ring that two friends share - one friend scrambles the message, the other uses the same ring to read it.

### How does the scrambling work?

Imagine you have a deck of 8 cards. The scrambling process goes like this:

1. **Shuffle the deck** - rearrange the cards in a specific pattern (this is called the Initial Permutation). Everyone uses the same pattern - it is not secret.
2. **Split the deck in half** - you now have a left pile and a right pile, 4 cards each.
3. **Season the right pile** - take the right pile, stretch it out, mix in half of your secret key, run it through a pair of lookup tables (called S-boxes - think of them as scrambling dictionaries that turn one pattern into a completely different pattern), and combine the result with the left pile. This is one "round" of scrambling.
4. **Swap the piles** and do it again with the other half of the key.
5. **Unshuffle the deck** - reverse the initial rearrangement.

The secret key itself gets split into two smaller keys (K1 and K2) through its own shuffling process. K1 is used in round 1, K2 in round 2.

To unscramble, you run the exact same process but use the keys in reverse order (K2 first, then K1). It is like a combination lock that opens when you enter the code backwards.

### Two ways to encrypt longer messages

Since S-DES only handles one byte (one character) at a time, you need a strategy for whole sentences:

- **ECB (Electronic Codebook)** - encrypt each letter separately. This is simple but has a flaw: if your message has two identical letters, they produce identical scrambled output. It is like a substitution cipher where "A" always becomes "X" - a pattern an attacker could spot.
- **CBC (Cipher Block Chaining)** - before encrypting each letter, mix it with the scrambled version of the previous letter. Now the same letter produces different output depending on its position. The very first letter has no "previous" letter, so you provide a random starting value called an IV (Initialization Vector).

### Why learn S-DES?

S-DES is far too weak for real security - there are only 1,024 possible keys, so a computer could try every single one in a fraction of a second. But it teaches you the building blocks that real encryption systems use: key schedules, rounds, substitution boxes, and block cipher modes. Once you understand S-DES, you understand the skeleton of AES and DES too.

Simplified DES (S-DES) is a teaching version of the Data Encryption Standard, designed by Edward Schaefer in 1996. Think of full DES as an industrial lock with 16 tumblers and a 56-bit key - S-DES is a miniature model of the same lock with just 2 tumblers and a 10-bit key. It is small enough to trace every step on paper, but uses the exact same locking mechanism.

### How it works

S-DES is a **Feistel cipher** - imagine a recipe where you split your ingredients into two bowls, season one bowl using a secret spice blend, mix the result into the other bowl, swap the bowls, and repeat. That is essentially what each round does with data.

The algorithm has three stages:

1. **Key schedule** - your 10-bit master key is shuffled (P10 permutation), split into two 5-bit halves, and each half is rotated left. An 8-bit subkey K1 is picked from the combined halves. The halves are rotated again and a second subkey K2 is picked. Think of it as cutting a master key into two slightly different copies for two rounds of locking.
2. **Encryption rounds** - the 8-bit plaintext goes through an initial shuffle (IP), then two rounds of the Feistel function with a swap in between, and a final unshuffle (inverse IP). The initial and final shuffles are like rearranging cards in a deck before and after the real mixing.
3. **The Feistel function (fK)** - the right half is expanded from 4 bits to 8, XORed with the round's subkey (mixing in the secret), run through two S-boxes (lookup tables that squash 4 bits down to 2 - the only non-linear, "unpredictable" part of the cipher, like a substitution table that scrambles letters), and the result is combined with the left half.

### Key properties

- **Symmetric** - the same key locks and unlocks. Decryption runs the identical process but applies the subkeys in reverse order (K2 first, then K1) - like turning the same key the other direction.
- **Block cipher** - operates on fixed 8-bit blocks, one byte at a time. To encrypt a whole message you need a mode of operation.
- **ECB vs CBC** - in ECB (Electronic Codebook) mode, each byte is encrypted independently. This is fast but has a weakness: identical input bytes always produce identical output bytes, like a codebook where "A" always becomes "X." In CBC (Cipher Block Chaining) mode, each byte is mixed with the previous ciphertext byte before encryption, breaking the pattern - the same letter encrypted twice produces different outputs depending on what came before it.
- **Educational only** - with only 1,024 possible keys, S-DES can be cracked in milliseconds. It exists to teach the structure of real block ciphers, not to secure anything.

## S-DES - How to Use It

From the main menu, press **1** to open the S-DES section. A default key is already loaded for you (`1010000010`), so you can start experimenting right away.

### Option 1 - Pick your secret key

Your key is 10 binary digits - just a sequence of 0s and 1s, like `1100011110`. You can type your own or press `r` to let the toolkit pick a random one. This key stays active for everything you do in the S-DES section until you change it. Think of it as choosing which decoder ring to use.

### Option 2 - See how the key splits

This shows you, step by step, how your 10-digit key gets turned into two smaller 8-digit keys (K1 and K2). It is like watching the locksmith cut two slightly different keys from one blank. Useful if you are working through a textbook example and want to check your hand calculations.

### Option 3 - Encrypt one block (with full trace)

Type in 8 binary digits (e.g. `10010111`) and watch the toolkit scramble them. Every single step is printed: the initial shuffle, the expansion, the key mixing, the S-box lookups, the swap between rounds, and the final unshuffle. It is like watching a magic trick in slow motion so you can see exactly how the coin disappears. The output is another 8 binary digits - the scrambled version.

### Option 4 - Decrypt one block (with full trace)

The reverse of option 3. Paste in 8 scrambled digits and get the original back, with the same step-by-step trace. You will see the keys are used in the opposite order - that is all that changes between encrypting and decrypting.

### Option 5 - Encrypt a whole message

Type any text (like `HELLO`). Choose your mode:

- **ECB** - each letter is encrypted on its own. Fast and simple.
- **CBC** - each letter is mixed with the previous result before encrypting. More secure, but you need to provide an 8-digit IV (starting value).

The output is a hex string - a compact way to write the scrambled bytes.

### Option 6 - Decrypt a message

Paste the hex string from option 5 and choose the same mode (and the same IV, if you used CBC). The toolkit unscrambles it back to readable text. If you use the wrong key, mode, or IV, you get garbage instead - which is exactly the point of encryption.

### Try it yourself

1. Press 1 and set the key to `1010000010`
2. Press 3 and encrypt `10010111` - you should get `00111000`
3. Press 4 and decrypt `00111000` - you should get `10010111` back
4. Press 5 and encrypt `HELLO` in CBC mode with IV `10101010`
5. Press 6 and decrypt the hex output using the same settings - you should get `HELLO` back

From the main menu, press **1** to enter the S-DES submenu. A default key (`1010000010`) is loaded automatically.

### Option 1 - Set key

Type a 10-bit binary string (e.g. `1100011110`) or press `r` to generate a random key. The key persists across all S-DES operations until you change it again. Every key schedule, encryption and decryption in this submenu uses the current key.

### Option 2 - Show key schedule (K1, K2)

Displays the full key derivation trace: the P10 permutation, the left-shifted halves after LS-1, the extracted K1 (via P8), the halves after LS-2, and the extracted K2. Use this to verify hand calculations or understand how the two 8-bit subkeys are derived from the 10-bit master key.

### Option 3 - Encrypt an 8-bit block

Enter an 8-bit binary plaintext (e.g. `10010111`). The toolkit encrypts it and prints a detailed round trace showing every intermediate value: the Initial Permutation, the Expansion/Permutation, the XOR with K1, the S-box outputs, the P4 permutation, the swap, the second round with K2, and the final Inverse IP. The ciphertext is an 8-bit binary string.

### Option 4 - Decrypt an 8-bit block

The mirror of option 3. Enter an 8-bit ciphertext and get the plaintext back, with the same round trace (subkeys applied in reverse order: K2 first, then K1).

### Option 5 - Encrypt text (ECB or CBC)

Enter any text string (e.g. `HELLO`). Choose ECB or CBC mode. In CBC mode, you also provide an 8-bit Initialization Vector. Each byte of the UTF-8 text is encrypted as one 8-bit block. The output is a hex string representing the ciphertext bytes.

### Option 6 - Decrypt hex (ECB or CBC)

Paste the hex ciphertext from option 5 (e.g. `a3f1b20c9e`). Choose the same mode and IV used during encryption. The toolkit decrypts each byte and prints the recovered plaintext text.

### Quick example

1. Set key to `1010000010` (option 1)
2. Encrypt block `10010111` (option 3) - produces `00111000`
3. Decrypt block `00111000` (option 4) - recovers `10010111`
4. Encrypt `HELLO` in CBC mode with IV `10101010` (option 5) - produces a hex string
5. Decrypt that hex in CBC mode with the same IV (option 6) - recovers `HELLO`

## RSA - The Concept

With S-DES, both the sender and receiver need the same secret key - like two friends sharing the same diary lock combination. But how do they agree on that combination in the first place without someone overhearing? RSA solves this problem by giving everyone two keys instead of one.

### The mailbox analogy

Imagine you install a mailbox on your front door with a slot anyone can drop letters into, but only you have the key to open it. The slot is your **public key** - you give it to the whole world. The key to the mailbox is your **private key** - you never share it with anyone. Anyone can send you a secret message by dropping it through the slot, but only you can read it.

### How are the keys made?

The trick behind RSA is a simple fact about numbers: multiplying two big prime numbers together is easy, but looking at the result and figuring out which two primes made it is incredibly hard. It is like mixing yellow and blue paint to get green - mixing is easy, but separating the green back into yellow and blue is practically impossible.

Here is the recipe, step by step:

1. **Pick two secret prime numbers** - call them p and q. A prime number is one that can only be divided by 1 and itself (like 7, 13, or 61). In the real world these are hundreds of digits long. In the toolkit you can use small ones like 61 and 53 to see the maths clearly.
2. **Multiply them together** to get n = p x q. This number n is made public. Even though everyone can see n, they cannot figure out p and q (when the numbers are big enough).
3. **Calculate a helper number** called phi = (p - 1) x (q - 1). This is the secret ingredient. You need to know p and q to calculate it - that is the whole trick.
4. **Choose a public exponent e** - a number that works well with phi. The standard choice is 65537. Think of this as the setting on your public mailbox slot.
5. **Calculate the private exponent d** - a special number that "undoes" what e does. You need phi to find d, and you need p and q to find phi. This is your mailbox key.

Your **public key** is the pair (e, n) - publish it everywhere. Your **private key** is the pair (d, n) - keep it secret.

### Locking and unlocking

To send someone a secret message, you take their public numbers (e, n) and do a mathematical operation on your message. To read it, they use their private number d. The maths guarantees that these two operations perfectly undo each other - like locking a padlock and then opening it.

The toolkit encrypts text one letter at a time: each character is converted to a number (A = 65, B = 66, etc.) and scrambled using the public key. The recipient unscrambles each number with the private key.

### Signing - proving you wrote it

RSA can also work in reverse to create digital signatures, which prove that a message really came from you and has not been tampered with:

1. **Sign** - run your message through a fingerprinting process (SHA-256 hashing - more on this in the Hashing section) to get a unique fixed-size summary, then scramble that summary with your private key. Only you could have done this.
2. **Verify** - anyone can unscramble the signature with your public key and compare the result to their own fingerprint of the message. If they match, the signature is genuine - like checking that a wax seal matches the expected stamp and has not been broken.

### Why RSA changed everything

Before RSA (invented in 1977), two people who wanted to communicate secretly had to meet in person first to share a key - like exchanging diary lock combinations face to face. RSA made it possible for complete strangers to communicate securely over the internet. When you see a lock icon in your browser, RSA (or its modern cousin ECC) is part of what makes that work.

RSA (named after its inventors Rivest, Shamir and Adleman, 1977) is the grandfather of public-key cryptography. Unlike S-DES where both sides share one secret key - like two people sharing the same house key - RSA gives everyone their own **key pair**: a public key they can hand out to anyone, and a private key they keep secret. Anyone can lock a box with your public padlock, but only you have the combination to open it.

### Key generation - building the trapdoor

The clever trick behind RSA is that multiplying two large prime numbers together is easy, but figuring out which two primes were used (factoring) is extremely hard. It is like mixing two colours of paint - easy to stir together, nearly impossible to separate.

Here is how the keys are built:

1. **Pick two secret prime numbers** p and q. In real systems these are hundreds of digits long. The toolkit lets you use small ones (like 61 and 53) for learning, or generate random ones up to 2048 bits for realism.
2. **Multiply them** to get n = p x q. This modulus is public - everyone can see n, but nobody can figure out p and q from it (for large enough primes).
3. **Compute the totient** phi(n) = (p - 1) x (q - 1). This number counts how many integers play nicely with n, and it is the secret ingredient that makes the maths work. You need p and q to compute it - that is the trapdoor.
4. **Choose a public exponent e** - a number that has no common factors with phi(n). The standard choice is 65537. Think of e as the setting on your public padlock.
5. **Compute the private exponent d** - the mathematical inverse of e with respect to phi(n). Knowing phi(n) makes this trivial; without it, it is as hard as factoring n. Think of d as the secret combination that undoes what e does.

The **public key** is (e, n) - share it freely. The **private key** is (d, n) - guard it.

### Encryption and decryption

To encrypt a message m (a number smaller than n):

- Ciphertext c = m raised to the power e, then divided by n, keeping only the remainder

To decrypt:

- Plaintext m = c raised to the power d, then divided by n, keeping only the remainder

The maths guarantees that raising to e and then to d always brings you back to the original number - like locking a padlock and then opening it with the combination. The toolkit encrypts text one byte at a time: each character's numeric value (0-255) is treated as a separate message. This is the textbook approach for learning - real RSA adds random padding to prevent pattern attacks.

### Digital signatures - proving who sent it

RSA can also work in reverse to sign messages, like a wax seal that proves a letter came from you and has not been tampered with:

1. **Sign** - hash the message with SHA-256 to get a fixed-size fingerprint, then raise that fingerprint to the power d (your private key). The result is the signature - only you could have produced it.
2. **Verify** - anyone can raise the signature to the power e (your public key) and check if the result matches the SHA-256 hash of the message. If it does, the signature is genuine.

### Why it matters

Before RSA, two people who wanted to communicate secretly had to first meet in person (or use a trusted courier) to agree on a shared key. RSA eliminated that problem entirely - you can post your public key on a website, and a stranger on the other side of the world can send you a message only you can read. RSA is still widely used in TLS (the lock icon in your browser), SSH, PGP email encryption and code signing, though ECC is increasingly preferred for its smaller keys.

## RSA - How to Use It

From the main menu, press **2** to open the RSA section. You will need to set up keys before doing anything else - the toolkit starts with no keys loaded.

### Option 1 - Generate random keys

Tell the toolkit how big you want your keys to be (between 16 and 2048 bits). It picks two random prime numbers, multiplies them, and computes everything for you. All six values are printed: the two primes (p, q), their product (n), the helper number (phi), the public exponent (e), and the private exponent (d). Start with 64 bits for a quick experiment. Use 2048 bits if you want to see real-world scale (it takes a moment longer).

### Option 2 - Enter keys by hand (textbook mode)

Perfect for working through classroom examples. Type in your own two primes and a public exponent. The classic textbook example is p = 61, q = 53, e = 17 - the toolkit will compute d = 2753 for you. It checks that your numbers are actually prime, that they are different, and that everything fits together correctly. If something is wrong, it tells you why.

### Option 3 - Show your keys

Forgot what keys you set? This prints them all again. Handy when you leave to try another tool and come back.

### Option 4 - Encrypt a message

Type any text (like `HELLO`). The toolkit converts each letter to its number (H = 72, E = 69, etc.) and scrambles it with the public key. The first three letters are shown step by step so you can follow the maths. The output is a list of numbers separated by spaces - each number is one scrambled letter.

### Option 5 - Decrypt a message

Paste the space-separated numbers from option 4. The toolkit unscrambles each one with the private key and converts them back to letters. Again, the first three are shown step by step. If any unscrambled number is bigger than 255 (the range of a single character), the toolkit warns you - this usually means you are using the wrong key.

### Option 6 - Sign a message

Type a message (like `pay Alice 10`). The toolkit creates a unique fingerprint of the message (using SHA-256), then scrambles that fingerprint with your private key. The result is a number called the signature. Only someone with your private key could produce this exact number for this exact message.

### Option 7 - Verify a signature

Type the original message and paste the signature number. The toolkit unscrambles the signature with the public key and checks whether it matches a fresh fingerprint of the message. It reports VALID (the signature is real and the message has not been changed) or INVALID (something does not match - either the message was altered, the signature is fake, or the wrong key was used).

### Try it yourself

1. Enter keys by hand: p = 61, q = 53, e = 17 (option 2)
2. Encrypt `HELLO` (option 4) - you get five numbers
3. Decrypt those five numbers (option 5) - you get `HELLO` back
4. Sign `pay Alice 10` (option 6) - you get a signature number
5. Verify `pay Alice 10` with that signature (option 7) - reports VALID
6. Now try verifying `pay Alice 99` with the same signature - reports INVALID, proving the signature protects the exact message

From the main menu, press **2** to enter the RSA submenu. No keys are loaded initially - you must generate or enter them before encrypting, decrypting or signing.

### Option 1 - Generate random keys

Enter a modulus size between 16 and 2048 bits. The toolkit picks two random primes of approximately half that size, computes n, phi(n), chooses e (65537 when the modulus is large enough, otherwise 3), and derives d. All six values (p, q, n, phi, e, d) are printed. Larger keys take longer to generate but are more realistic - 64 bits is a good default for interactive exploration, 2048 for real-world scale.

### Option 2 - Enter p, q, e manually (textbook mode)

For hand-worked examples straight from a textbook. Enter two distinct primes (e.g. p = 61, q = 53) and a public exponent e (e.g. 17). The toolkit validates that both inputs are prime, that they are different, that n > 255 (so each byte fits in one block), and that gcd(e, phi) = 1. It then computes and displays d and all other values. The classic textbook example p = 61, q = 53, e = 17 gives d = 2753.

### Option 3 - Show keys

Prints the current key set: p, q, n, phi(n), e, d, and the modulus bit length. Use this to recall your keys after switching to another submenu and back.

### Option 4 - Encrypt text

Enter a plaintext string (e.g. `HELLO`). Each byte of the UTF-8 encoding is encrypted individually as m^e mod n. The first three encryptions are shown step by step (m = byte value, ciphertext = m^e mod n). The output is a space-separated list of numbers, each one a ciphertext block.

### Option 5 - Decrypt numbers

Paste the space-separated ciphertext numbers from option 4. Each number is decrypted as c^d mod n and converted back to a byte. The first three decryptions are shown step by step. If any decrypted value exceeds 255, the toolkit warns you - this usually means you are using the wrong key.

### Option 6 - Sign a message

Enter a message (e.g. `pay Alice 10`). The toolkit computes SHA-256 of the message, reduces it mod n, and signs it by raising the hash to the power d mod n. Both the hash and the signature are printed. If n is smaller than 256 bits, a note reminds you the hash was truncated (for demonstration purposes only).

### Option 7 - Verify a signature

Enter the original message and the signature number. The toolkit recomputes the SHA-256 hash, raises the signature to the power e mod n, and checks if the recovered hash matches. It reports VALID or INVALID.

### Quick example

1. Enter keys manually: p = 61, q = 53, e = 17 (option 2) - d computes to 2753
2. Encrypt `HELLO` (option 4) - produces five ciphertext numbers
3. Decrypt those numbers (option 5) - recovers `HELLO`
4. Sign `pay Alice 10` (option 6) - produces a signature number
5. Verify the same message with that signature (option 7) - reports VALID
6. Verify a tampered message like `pay Alice 99` with the same signature - reports INVALID

## ECC - The Concept

ECC stands for Elliptic Curve Cryptography. It does the same job as RSA - public key, private key, encryption, signatures - but it is the newer, more efficient version. An ECC key of 256 bits gives you the same security as an RSA key of 3,072 bits. Think of RSA as a big heavy padlock and ECC as a small titanium one - equally hard to break, but lighter and faster.

### What is an elliptic curve?

Forget everything you know about ellipses - an "elliptic curve" is actually a smooth, looping shape on a graph. The toolkit gives you two to play with:

- **The toy curve** - a tiny version with only 19 valid points. Imagine a clock face with 19 positions instead of 12. You can list every position and follow every step by hand. Great for learning.
- **secp256k1** - the real curve used by Bitcoin. Same rules, but with more valid points than there are atoms in the universe. This is what the real world uses.

### The magic trick: point addition

The entire security of ECC comes from one clever operation called "point addition." Here is the idea:

Take two points on the curve. Draw a straight line through them. That line will hit the curve at exactly one more place. Flip that place upside down, and you have your answer. That is how you "add" two points together.

You can also add a point to itself (called "doubling") by drawing a line that just touches the curve at that point.

By combining doubling and adding, you can jump from the starting point (called G, the "generator") to any other point on the curve. Jump 7 times and you land on one specific point. Jump 1,000 times and you land on a completely different one.

### The one-way street

Here is why ECC is secure: jumping forward is fast (the toolkit can do it in under a second even for huge numbers), but figuring out how many jumps someone made is practically impossible.

Your **private key** is a secret number - say 7. Your **public key** is the point you land on after jumping 7 times from G. Anyone can see where you landed, but they cannot figure out that you jumped exactly 7 times. On the real curve, your secret number is 256 bits long, making it completely impossible to guess.

### Three things ECC can do

**Key exchange (ECDH)** - Alice and Bob each pick a secret number and publish where they land. Alice jumps her secret number of times from Bob's landing spot. Bob jumps his secret number of times from Alice's landing spot. They both end up at the same place - a shared secret. An eavesdropper who sees both public landing spots cannot figure out the shared secret. It is like two people each privately mixing a colour into the other person's public paint - they both end up with the same shade, but nobody watching can recreate it.

**Digital signatures (ECDSA)** - Alice creates a fingerprint of her message, mixes it with her private key and a one-time random number, and produces a signature (two numbers, r and s). Anyone with her public key can check the signature. It proves Alice wrote it and the message has not been changed - like a tamper-evident seal.

**Encryption (ECIES)** - To send a secret message to someone, you create a temporary shared secret using their public key (like half of a key exchange), use that secret to scramble your message, and send the scrambled text along with enough information for the recipient (and only the recipient) to recreate the temporary secret and unscramble it.

Elliptic Curve Cryptography (ECC) is the modern successor to RSA. It does the same job - public key, private key, encryption, signatures - but with much smaller keys. A 256-bit ECC key is roughly as strong as a 3072-bit RSA key. Think of it as a newer, more compact lock that is just as hard to pick.

### The curve - a mathematical playground

Picture a smooth, looping curve drawn on a sheet of graph paper. The equation is y squared = x cubed + ax + b, and only the points that land exactly on that curve are valid "addresses" in the system. The toolkit offers two curves:

- **Toy curve** (p = 17) - a tiny curve with only 19 points. Think of it as a small circular track with 19 marked positions. You can list every position and trace every step by hand.
- **secp256k1** - the real curve used by Bitcoin. It has roughly 2^256 valid points - more than the number of atoms in the observable universe. Same rules, just an enormously bigger track.

### Point addition - the core trick

The magic of ECC is a special way to "add" two points on the curve. Imagine two dots on the curve. Draw a straight line through them - it hits the curve at exactly one more spot. Flip that spot across the horizontal axis, and that is your answer. This is point addition.

When you add a point to itself ("doubling"), you draw the tangent line at that point instead. By repeating this - double, add, double, add - you can compute any multiple: 2G, 3G, 7G, 1000G, where G is a fixed starting point everyone agrees on (the "generator").

### The trapdoor - easy one way, impossible the other

Your private key is just a secret number d. Your public key is Q = d x G (the generator added to itself d times). Computing Q from d is fast - the toolkit uses a shortcut called "double-and-add" that takes at most 256 steps even for huge numbers.

But going backwards - figuring out d when you only know Q and G - is like being told "I walked some number of laps around a circular track and ended up at this marker. How many laps?" On a track with 2^256 markers, there is no shortcut. You would have to try every possible number of laps. This one-way difficulty is what makes ECC secure.

### Three things ECC can do

**ECDH (key exchange)** - Alice and Bob each pick a secret number and publish the matching public point. Alice multiplies her secret by Bob's public point; Bob does the reverse. They both arrive at the same shared secret - like two people each mixing their private paint colour into the other person's public colour and ending up with the same shade, while an eavesdropper who only saw the public colours cannot reverse the mixing.

**ECDSA (digital signatures)** - Alice hashes her message, combines the hash with her private key and a one-time random number, and produces two numbers (r, s) as the signature. Anyone with her public key can check that those two numbers match the message. It proves Alice signed it and the message was not altered - like a wax seal that cracks if the envelope is opened.

**ECIES (encryption)** - To send a secret message to someone, you generate a one-time random number, compute a temporary shared secret from the recipient's public key (like a half-ECDH exchange), and use that secret to scramble the message. You send the scrambled text along with a public "receipt" (the ephemeral point R) so the recipient can recreate the same temporary secret with their private key and unscramble it. Think of it as locking a letter in a box using a temporary key derived from the recipient's public padlock, then taping the receipt to the box so only they can recreate the key.

## ECC - How to Use It

From the main menu, press **3** to open the ECC section. It starts on the real Bitcoin curve (secp256k1), but you can switch to the tiny toy curve to see everything clearly.

### Option 1 - Switch curves

Type `t` for the toy curve (19 points, perfect for learning) or `s` for secp256k1 (the real one). Switching clears your keys because keys belong to a specific curve - a key made on one curve means nothing on another, like a house key that only fits one lock.

### Option 2 - See the curve

Shows you the curve's settings: the size of the field, the shape of the curve, the starting point G, and how many valid points exist. On the toy curve, it lists all 19 points so you can see the entire playground at once.

### Option 3 - Play with point maths

Two modes:

- **k x G with trace** - type a number and watch the toolkit jump that many times from the starting point, step by step. You see every "double" and "add" along the way. On the toy curve with a small number, this is a great way to see how points move around the curve.
- **aG + bG** - type two numbers. The toolkit computes each jump separately, then adds the landing spots together. It also computes (a+b) x G directly. The results match - proving that jumping 3 times then 5 more times lands you at the same place as jumping 8 times.

### Option 4 - Create a key pair

Type a private key (any number) or press `r` for a random one. The toolkit jumps that many times from G and shows you where you land - that landing spot is your public key. Think of picking a secret number of steps on a circular track. Everyone can see where you ended up, but nobody can figure out how many steps you took.

### Option 5 - Key exchange (ECDH)

The toolkit runs a full key exchange automatically. It creates Alice and Bob, gives each a random secret number, computes their public landing spots, and then shows each person jumping their secret number from the other's public point. They both arrive at the same shared secret. It also hashes the shared secret into a usable key.

### Option 6 - Sign a message (ECDSA)

You need a key pair first (option 4). Type a message and the toolkit produces a signature - two numbers called r and s. These two numbers are tied to both the message and your private key. Change either one and the signature breaks.

### Option 7 - Verify a signature (ECDSA)

Type the original message and paste the r and s numbers from option 6. The toolkit checks whether the signature is valid using only the public key. It reports VALID or INVALID. Try changing one letter of the message - it will report INVALID, proving the signature protects every single character.

### Option 8 - Encrypt a message (ECIES)

You need a key pair first. Type some text and the toolkit scrambles it using a temporary shared secret derived from the recipient's public key. The output is two things: an ephemeral point R (a kind of receipt) and the scrambled text as hex.

### Option 9 - Decrypt a message (ECIES)

Paste the ephemeral point R and the hex ciphertext from option 8. The toolkit uses your private key to recreate the temporary shared secret and unscramble the message.

### Try it yourself

1. Switch to the toy curve (option 1, type `t`) - small enough to see everything
2. List all 19 points (option 2)
3. Watch 7 x G step by step (option 3)
4. Create a key pair (option 4)
5. Sign `hello ecc` (option 6) - get r and s
6. Verify `hello ecc` with that r and s (option 7) - reports VALID
7. Encrypt `SECRET` (option 8) - get R and hex ciphertext
8. Decrypt with R and the hex (option 9) - get `SECRET` back

From the main menu, press **3** to enter the ECC submenu. The toolkit starts on the real-world secp256k1 curve (the one Bitcoin uses), but you can switch to a tiny toy curve to see every point and trace every step.

### Option 1 - Switch curve

Type `t` for the toy curve or `s` for secp256k1. Switching curves clears your key pair, since keys are tied to their curve - like a house key that only fits one lock. The toy curve has just 19 points, making it perfect for following the maths on paper. secp256k1 has roughly 2^256 points - real-world scale.

### Option 2 - Show curve parameters

Prints the curve's equation and constants: the prime p (the size of the "field" the curve lives in), the coefficients a and b, the generator point G, and the order n (how many times you can add G to itself before looping back to the start). On the toy curve, it also lists every single point - like seeing every seat in a small room.

### Option 3 - Point arithmetic

Two sub-options:

- **k \* G with trace** - enter a number k and watch the toolkit compute k times the generator, step by step. Each "double" and "add" is printed as it happens - like watching someone count laps on a track. On the toy curve with small k, you see every intermediate point.
- **aG + bG** - enter two numbers a and b. The toolkit computes aG and bG separately, then adds them together, and also computes (a+b)G directly. The two results match - this demonstrates that point addition is consistent, like showing that walking 3 blocks then 5 blocks lands you at the same place as walking 8 blocks.

### Option 4 - Generate key pair

Enter a private key d (any number from 1 to n-1) or press `r` for a random one. The toolkit computes the public key Q = d x G. Think of d as a secret combination and Q as the padlock it opens - you can hand out the padlock freely, but only you know the combination.

### Option 5 - ECDH key exchange

The toolkit simulates a full key exchange between Alice and Bob automatically. It generates random private keys for both, computes their public keys, then shows each person multiplying their private key by the other's public key. Both arrive at the same shared secret point S - like two painters mixing private colours into each other's public paint and ending up with the same shade. The SHA-256 hash of S is printed as a usable shared key.

### Option 6 - ECDSA sign

Requires a key pair (option 4 first). Enter a message and the toolkit produces a signature: two numbers r and s. Behind the scenes, it hashes the message with SHA-256, picks a one-time random number k, and combines everything with your private key. The signature is like a wax seal - unique to both the message and the signer.

### Option 7 - ECDSA verify

Enter the original message plus the r and s values from option 6. The toolkit checks whether the signature is valid using the public key alone - no private key needed. If anyone changed even one character of the message, it reports INVALID. Think of it as checking whether a wax seal is intact and matches the expected stamp.

### Option 8 - Encrypt text (ECIES-style)

Requires a key pair. Enter text and the toolkit encrypts it to your public key using a one-time shared secret - like putting a letter in a box, locking it with a temporary key derived from the recipient's padlock, and taping the padlock's receipt (the ephemeral point R) to the outside. The output is R (a point) and the ciphertext (hex).

### Option 9 - Decrypt text

Paste the ephemeral point R and ciphertext hex from option 8. The toolkit uses your private key to recompute the shared secret and recover the plaintext - like using your combination to recreate the temporary key and open the box.

### Quick example

1. Switch to the toy curve (option 1, type `t`)
2. Show all 19 curve points (option 2)
3. Compute 7 x G with a step-by-step trace (option 3)
4. Generate a key pair (option 4)
5. Sign `hello ecc` (option 6) - get r and s
6. Verify with the same message and signature (option 7) - reports VALID
7. Encrypt `SECRET` (option 8) - get R and ciphertext
8. Decrypt with R and the ciphertext (option 9) - recovers `SECRET`

## Hashing - The Concept

Imagine you have a paper shredder that always shreds a document into exactly the same pattern of confetti. Hand it the same letter twice and you get identical confetti both times. Hand it a different letter - even one with just a single changed word - and the confetti looks completely different.

That is what a hash function does. It takes any input - a word, a sentence, an entire book - and produces a fixed-size "fingerprint." The same input always gives the same fingerprint, but even the tiniest change produces a completely different one.

### Why is this useful?

Hash functions solve a simple problem: how do you check whether something has been changed without comparing every single character?

Think of it like a wax seal on an envelope. You don't need to read the entire letter to know it hasn't been tampered with - just check if the seal is intact. A hash works the same way. You compute the fingerprint before sending, and the recipient computes it again after receiving. If the two fingerprints match, the message arrived untouched.

### One-way only

The most important property of a hash is that it only works in one direction. You can turn a message into a fingerprint, but you cannot turn the fingerprint back into the message. It's like baking a cake - you can't un-bake it back into eggs, flour, and sugar.

This is why hashing is used for storing passwords. A website stores the hash of your password, not the password itself. When you log in, it hashes what you typed and compares the two fingerprints. Even if someone steals the database, they only get fingerprints - not the actual passwords.

### The avalanche effect

Change one letter in your input and the entire fingerprint changes. Not just one character of it - the whole thing looks completely different. This is called the avalanche effect.

Example:

- "hello" might hash to `2cf24dba5fb0a30e...`
- "Hello" (capital H) might hash to `185f8db32271fe25...`

They share almost nothing in common, even though the inputs differ by just one letter. This makes it impossible to guess what was changed by looking at two fingerprints.

### Two algorithms: SHA-256 and MD5

This toolkit includes two hash algorithms:

**SHA-256** produces a 256-bit fingerprint (64 hex characters). It is the modern standard - used in Bitcoin, SSL certificates, and software downloads. Think of it as a high-security wax seal that nobody has figured out how to forge.

**MD5** produces a 128-bit fingerprint (32 hex characters). It is older and faster but has a known weakness: researchers have found ways to create two different documents that produce the same MD5 fingerprint (called a "collision"). Think of it as a padlock where someone discovered the master key. It still works for checking accidental changes (like verifying a downloaded file wasn't corrupted) but should never be used for security.

### Collisions

A collision happens when two different inputs produce the same fingerprint. Since fingerprints have a fixed size but inputs can be anything, collisions must mathematically exist - there are infinitely many possible inputs but only a finite number of fingerprints.

For SHA-256, finding a collision on purpose is so astronomically difficult that it has never been done. For MD5, researchers demonstrated practical collisions in 2004, which is why the security world moved on to SHA-256.

### Real-world uses

- **Password storage** - websites store hashes, not passwords
- **File integrity** - download sites list the SHA-256 hash so you can verify your copy matches
- **Digital signatures** - sign the hash of a document instead of the entire document (much faster)
- **Blockchain** - Bitcoin miners race to find inputs that produce hashes starting with a certain number of zeros
- **Data deduplication** - cloud storage hashes each file to detect duplicates without comparing every byte

A hash function is a one-way fingerprint machine. You feed in data of any size - a single word, a novel, an entire movie file - and it produces a fixed-size output called a digest. SHA-256 always produces 256 bits (64 hex characters). MD5 always produces 128 bits (32 hex characters). No matter how big or small the input, the output is always the same length.

### The one-way property

Hashing is like putting a document through a paper shredder that always produces exactly 64 strips. You can shred any document and get 64 strips, but you cannot reassemble the original document from the strips. Given a hash digest, there is no practical way to work backwards and find the original input. This is what makes hashing useful for storing passwords - a website stores the hash of your password, not the password itself. When you log in, it hashes what you typed and compares the two hashes.

### Collision resistance

A good hash function makes it practically impossible to find two different inputs that produce the same digest (a "collision"). Think of it like fingerprints - in theory, two people could share the same fingerprint, but the chances are so astronomically small that fingerprints are treated as unique identifiers.

SHA-256 has never had a collision found. MD5, on the other hand, was broken in 2004 - researchers found a way to deliberately create two different files with the same MD5 hash. This is why MD5 is considered insecure for any purpose that depends on collision resistance (like digital signatures or certificate verification), though it is still commonly used as a simple checksum.

### The avalanche effect

Change a single bit in the input and roughly half of the output bits flip. There is no pattern - the new hash looks completely unrelated to the old one. Imagine two nearly identical letters, one saying "pay $100" and the other "pay $900." Their hashes would be as different as two random strings. This property ensures that similar inputs do not produce similar outputs, making it impossible to guess the input by studying the hash.

### How SHA-256 works internally

SHA-256 follows the Merkle-Damgard construction - a general framework used by many hash functions:

1. **Padding** - the message is padded to a multiple of 512 bits. A `1` bit is appended, then enough `0` bits, then the original message length as a 64-bit number. This ensures every message has a unique padded form.
2. **Chunking** - the padded message is split into 512-bit blocks.
3. **Compression** - each block is processed through 64 rounds of mixing. Eight working variables (initialized from the square roots of the first eight primes) are scrambled using bitwise rotations, XORs, additions and lookups into a table of constants (derived from the cube roots of the first 64 primes). Each round feeds in one word of the expanded message block.
4. **Output** - after all blocks are processed, the eight working variables are concatenated to produce the 256-bit digest.

MD5 works similarly but with a simpler structure: four rounds of 16 operations each, 128-bit state, and weaker mixing functions - which is ultimately why it was broken.

### What hashing is used for

- **Integrity verification** - download a file and compare its hash to the published hash. If they match, the file was not corrupted or tampered with during transfer.
- **Password storage** - store hashes instead of passwords. Even if the database is stolen, the original passwords remain hidden.
- **Digital signatures** - RSA and ECDSA both hash the message first, then sign the hash. This keeps the signature a fixed size regardless of message length.
- **Data deduplication** - two files with the same hash are (almost certainly) identical, so only one copy needs to be stored.

## Hashing - How to Use It

From the main menu, press **4** to open the Hashing section. You will see four options.

### Option 1 - SHA-256 hash

Type any text and the toolkit computes its SHA-256 fingerprint - a 64-character hex string. Try it with a simple word like `hello`, then try `Hello` (capital H). The two fingerprints will look completely different, even though the inputs differ by just one letter. This is the avalanche effect in action.

### Option 2 - MD5 hash

Same idea, but produces a shorter 32-character hex fingerprint using the older MD5 algorithm. Try the same inputs you used for SHA-256 and compare - the MD5 fingerprints are shorter but still completely different from each other for even a tiny input change.

### Option 3 - Compare two texts

Type two pieces of text. The toolkit hashes both with SHA-256 and MD5, then tells you whether the fingerprints match. If you type the exact same text both times, both algorithms will report a match. Change even one character and both will report a mismatch.

This is the real-world use case: checking whether a file or message was changed. Download sites publish the SHA-256 hash of a file so you can verify your downloaded copy is identical to the original.

### Option 4 - Hash analysis

Type some text and the toolkit shows you a detailed breakdown of the hashing process:

- The raw bytes of your input (how the computer actually sees your text)
- Both the SHA-256 and MD5 fingerprints side by side
- The bit length of each fingerprint (256 bits vs 128 bits)
- A visual comparison so you can see how much longer and more secure SHA-256 is

This option is great for understanding why SHA-256 is considered stronger - with twice as many bits, the number of possible fingerprints jumps from about 340 undecillion (MD5) to about 115 quattuorvigintillion (SHA-256). That astronomical difference is what makes SHA-256 collisions practically impossible to find.

### Try it yourself

1. Hash `hello` with SHA-256 (option 1) - note the fingerprint
2. Hash `hello` with MD5 (option 2) - note the shorter fingerprint
3. Hash `Hello` with both - see how completely different they are from `hello`
4. Compare `hello` and `hello` (option 3) - reports MATCH
5. Compare `hello` and `Hello` (option 3) - reports MISMATCH
6. Run hash analysis on `hello` (option 4) - see the full breakdown
7. Try a long sentence, then change one word - watch both fingerprints change entirely

From the main menu, press **4** to enter the Hashing submenu. Both SHA-256 and MD5 are implemented from scratch in the toolkit - no external libraries - so you can see exactly how the algorithms behave.

### Option 1 - Hash text with both algorithms

Enter any text (e.g. `abc`) and the toolkit computes both the SHA-256 and MD5 digests side by side. The SHA-256 output is 64 hex characters long; the MD5 output is 32. Even a tiny input like a single letter produces a full-length, seemingly random hash. Try hashing `abc` and then `abd` - the outputs look completely unrelated despite the inputs differing by one letter.

### Option 2 - Hash a file

Enter a file path on your system. The toolkit reads the entire file (it shows the byte count) and computes both hashes. This is exactly how download verification works in the real world - a website publishes the SHA-256 hash of a file, and after downloading it you run the same hash locally. If they match, your copy is intact.

### Option 3 - Verify integrity

A practical integrity-check tool. Enter some text, choose SHA-256 or MD5, and paste the expected hash. The toolkit computes the hash of your text and compares it character by character. It reports MATCH (data is intact) or MISMATCH (the data was changed or the expected hash is wrong). Think of it as comparing two fingerprints side by side under a magnifying glass.

### Option 4 - Avalanche effect

The most visual demonstration in the toolkit. Enter some text (e.g. `The quick brown fox`). The toolkit flips just the lowest bit of the first byte - a change so small you can barely see it in the text - and then hashes both the original and the modified version. It counts how many of the 256 output bits (for SHA-256) and 128 bits (for MD5) changed. A well-designed hash function flips roughly 50% of the bits. You will typically see results like "131 of 256 bits changed (51.2%)" for SHA-256 - almost exactly half, from a single-bit change. This is the avalanche effect in action.

### Option 5 - Cross-check against Java's MessageDigest

This is a correctness test. The toolkit hashes several test strings (empty string, `abc`, long repeated strings) using its own from-scratch SHA-256 and MD5 implementations, then hashes the same strings using Java's built-in `MessageDigest` library, and compares every byte. It reports OK for each match. If all tests pass, you know the hand-written implementations produce bit-identical results to the standard library - like checking your hand-drawn map against a GPS.

### Quick example

- [ ] Hash `abc` with both algorithms (option 1) - SHA-256 should start with `ba7816bf`, MD5 with `90015098`
- [ ] Hash the same text in the integrity checker (option 3) with expected hash `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` - reports MATCH
- [ ] Run the avalanche demo (option 4) on `The quick brown fox` - see roughly half the bits change from one flipped input bit

Run the cross-check (option 5) - all tests should report OK, confirming the toolkit's implementations are correct
