import { Worker, isMainThread, workerData, parentPort } from "worker_threads";
import * as readline from "readline";
import chalk from "chalk";
const colorPalete = {
  primary: "#FFEAA7",
  secondary: "#DCFFB7",
  warn: "#FFBB64",
  error: "#FF6868",
};
class RSA {
  public static generateKeys(bitLength: number): {
    publicKey: string;
    privateKey: string;
  } {
    const p = RSA.generatePrime(bitLength / 2);
    const q = RSA.generatePrime(bitLength / 2);
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);

    let e = RSA.PUBLIC_EXPONENT;
    while (RSA.gcd(e, phi) !== 1n) {
      e = BigInt(Math.floor(Math.random() * Number(phi)));
    }

    const d = RSA.modInverse(e, phi);

    const publicKeyBase64 = Buffer.from(`${e},${n}`).toString("base64");
    const privateKeyBase64 = Buffer.from(`${d},${n}`).toString("base64");

    return {
      publicKey: publicKeyBase64,
      privateKey: privateKeyBase64,
    };
  }

  public static async encrypt(
    message: string,
    publicKey: string
  ): Promise<string> {
    return RSA.workerTask("encrypt", message, publicKey);
  }

  public static async decrypt(
    encryptedMessage: string,
    privateKey: string
  ): Promise<string> {
    return RSA.workerTask("decrypt", encryptedMessage, privateKey);
  }

  private static async workerTask(
    action: "encrypt" | "decrypt",
    message: string,
    key: string
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      if (isMainThread) {
        const worker = new Worker(__filename, {
          workerData: { action, message, key },
        });

        worker.on("message", resolve);
        worker.on("error", reject);
        worker.on("exit", (code) => {
          if (code !== 0)
            reject(new Error(`Worker stopped with exit code ${code}`));
        });
      } else {
        const { action, message, key } = workerData;
        const result =
          action === "encrypt"
            ? RSA.encryptWorker(message, key)
            : RSA.decryptWorker(message, key);
        parentPort?.postMessage(result);
      }
    });
  }

  public static encryptWorker(message: string, publicKey: string): string {
    const [e, n] = Buffer.from(publicKey, "base64")
      .toString()
      .split(",")
      .map(BigInt);
    let encrypted = "";
    for (let i = 0; i < message.length; i++) {
      const charCode = BigInt(message.charCodeAt(i));
      const encryptedChar = RSA.modPow(charCode, e, n);
      encrypted += `${encryptedChar},`;
    }
    return encrypted.slice(0, -1);
  }

  public static decryptWorker(
    encryptedMessage: string,
    privateKey: string
  ): string {
    const [d, n] = Buffer.from(privateKey, "base64")
      .toString()
      .split(",")
      .map(BigInt);
    let decrypted = "";
    const encryptedChars = encryptedMessage.split(",").map(BigInt);
    for (const encryptedChar of encryptedChars) {
      const charCode = Number(RSA.modPow(encryptedChar, d, n));
      decrypted += String.fromCharCode(charCode);
    }
    return decrypted;
  }

  private static gcd(a: bigint, b: bigint): bigint {
    while (b) {
      const t = b;
      b = a % b;
      a = t;
    }
    return a;
  }

  private static modPow(
    base: bigint,
    exponent: bigint,
    modulus: bigint
  ): bigint {
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
      if (exponent & 1n) {
        result = (result * base) % modulus;
      }
      base = (base * base) % modulus;
      exponent >>= 1n;
    }
    return result;
  }

  private static modInverse(a: bigint, m: bigint): bigint {
    let m0 = m;
    let x0 = 0n;
    let x1 = 1n;

    if (m === 1n) {
      return 0n;
    }

    while (a > 1n) {
      const q = a / m;
      let t = m;
      m = a % m;
      a = t;
      t = x0;
      x0 = x1 - q * x0;
      x1 = t;
    }

    if (x1 < 0n) {
      x1 += m0;
    }

    return x1;
  }

  private static generatePrime(bitLength: number): bigint {
    let prime: bigint;
    do {
      prime = RSA.generateRandomOddNumber(bitLength);
    } while (!RSA.millerRabinPrimalityTest(prime));
    return prime;
  }

  private static generateRandomOddNumber(bitLength: number): bigint {
    let randomBits = "1";
    for (let i = 1; i < bitLength; i++) {
      randomBits += Math.random() < 0.5 ? "0" : "1";
    }
    return BigInt("0b" + randomBits);
  }

  private static millerRabinPrimalityTest(n: bigint, k: number = 10): boolean {
    if (n < 2n) {
      return false;
    }
    if (n === 2n || n === 3n) {
      return true;
    }
    if (n % 2n === 0n) {
      return false;
    }

    let r = n - 1n;
    let s = 0n;
    while (r % 2n === 0n) {
      r >>= 1n;
      s += 1n;
    }

    for (let i = 0; i < k; i++) {
      const minRandom = n > 10n ? n - 10n : 2n;
      const a =
        BigInt(Math.floor(Math.random() * Number(n - minRandom))) + minRandom;
      let x = RSA.modPow(a, r, n);
      if (x !== 1n && x !== n - 1n) {
        let j = 1n;
        while (j < s && x !== n - 1n) {
          x = RSA.modPow(x, 2n, n);
          if (x === 1n) {
            return false;
          }
          j += 1n;
        }
        if (x !== n - 1n) {
          return false;
        }
      }
    }

    return true;
  }

  private static PUBLIC_EXPONENT = 65537n;
}

class ConsoleInterface {
  private static rl: readline.Interface;

  public static async askQuestion(query: string): Promise<string> {
    if (!ConsoleInterface.rl) {
      ConsoleInterface.rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });
    }

    return new Promise<string>((resolve) => {
      ConsoleInterface.rl.question(chalk.yellow(query), (answer) => {
        resolve(answer);
      });
    });
  }

  public static close(): void {
    if (ConsoleInterface.rl) {
      ConsoleInterface.rl.close();
    }
  }

  public static async displayFuturisticAnimation(): Promise<void> {
    console.log(
      chalk.hex(colorPalete.secondary)(
        "Welcome to RSA Encryption and Decryption"
      )
    );
  }

  public static async displayMenu(): Promise<void> {
    console.log(chalk.bold.hex(colorPalete.primary)("Menu:"));
    console.log(chalk.hex(colorPalete.secondary)("1. Create RSA Key"));
    console.log(chalk.hex(colorPalete.secondary)("2. Encrypt Message"));
    console.log(chalk.hex(colorPalete.secondary)("3. Decrypt Message"));
    console.log(chalk.hex(colorPalete.secondary)("4. Exit"));
  }

  public static async processChoice(choice: string): Promise<void> {
    switch (choice.trim()) {
      case "1":
        await ConsoleInterface.createRSAKey();
        break;
      case "2":
        await ConsoleInterface.encryptMessage();
        break;
      case "3":
        await ConsoleInterface.decryptMessage();
        break;
      case "4":
        ConsoleInterface.close();
        process.exit(0);
      default:
        console.log(
          chalk.hex(colorPalete.error)(
            "Invalid choice. Please enter a valid option."
          )
        );
    }
  }

  private static async createRSAKey(): Promise<void> {
    let bitLength: number;
    do {
      bitLength = parseInt(
        await ConsoleInterface.askQuestion(
          chalk.hex(colorPalete.primary)(
            "Enter the desired bit length for the keys (>=16): "
          )
        )
      );
      if (bitLength < 16) {
        console.error(
          chalk.red(
            "Bit length must be greater than or equal to 16. Please enter a valid value."
          )
        );
      }
    } while (bitLength < 16);
    if (16 < bitLength && bitLength < 1024) {
      console.warn(
        chalk.hex(colorPalete.warn)(
          "For production, bit length should be greater or equal to 1024. "
        )
      );
    }
    const { publicKey, privateKey } = RSA.generateKeys(bitLength);
    console.log(chalk.hex(colorPalete.secondary)("Public Key: "), publicKey);
    console.log(chalk.hex(colorPalete.secondary)("Private Key: "), privateKey);
  }

  private static validateKey(key: string): boolean {
    const unzipedKey = atob(key);
    const keyDatas = unzipedKey.split(",");

    if (keyDatas.length < 2) {
      return false;
    }

    return true;
  }
  private static async encryptMessage(): Promise<void> {
    const publicKey = await ConsoleInterface.askQuestion(
      chalk.hex(colorPalete.secondary)("Enter the RSA public key: ")
    );
    const isVaildKey = ConsoleInterface.validateKey(publicKey);
    do {
      if (isVaildKey) {
        const message = await ConsoleInterface.askQuestion(
          chalk.hex(colorPalete.secondary)("Enter the message to encrypt: ")
        );
        const encryptedMessage = await RSA.encrypt(message, publicKey);
        console.log(
          chalk.hex(colorPalete.primary)("Encrypted Message: "),
          encryptedMessage
        );
      } else {
        console.error(
          chalk.hex(colorPalete.error)(
            "This Public Key is Invaid. Generate another key"
          )
        );
        ConsoleInterface.close;
      }
    } while (isVaildKey === false);
  }

  private static async decryptMessage(): Promise<void> {
    const privateKey = await ConsoleInterface.askQuestion(
      chalk.hex(colorPalete.secondary)("Enter the RSA private key: ")
    );
    const encryptedMessage = await ConsoleInterface.askQuestion(
      chalk.hex(colorPalete.secondary)("Enter the encrypted message: ")
    );
    const decryptedMessage = await RSA.decrypt(encryptedMessage, privateKey);
    console.log(
      chalk.hex(colorPalete.primary)("Decrypted Message: "),
      decryptedMessage
    );
  }
}

// Main thread code
if (isMainThread) {
  async function main() {
    await ConsoleInterface.displayFuturisticAnimation();

    while (true) {
      await ConsoleInterface.displayMenu();
      const choice = await ConsoleInterface.askQuestion(
        chalk.hex(colorPalete.primary)("Enter your choice: ")
      );
      await ConsoleInterface.processChoice(choice);
    }
  }

  main();
} else {
  // Worker code
  const { action, message, key } = workerData;
  const result =
    action === "encrypt"
      ? RSA.encryptWorker(message, key)
      : RSA.decryptWorker(message, key);
  parentPort?.postMessage(result);
}
