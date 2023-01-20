import java.io.*;
import java.net.*;

class Client {
	// Declare p, g, and Key of client
	static int port = 10000, p = 100000000, g = 7, a = 6;
	static String pstr, gstr, Astr, serverName = "localhost";
	static double Adash, serverB;
	static DataOutputStream dos;
	static BufferedReader br, kb;
	static Socket s;

	public static void main(String args[]) throws Exception {
		try {

			System.out.println("Client Connected at port " + Integer.toString(port));

			s = new Socket("localhost", port); // Create client socket
			System.out.println("Just connected to " + s.getRemoteSocketAddress());

			// Secret Key Exchange (Diffie-Hellman)
			OutputStream outToServer = s.getOutputStream();
			DataOutputStream out = new DataOutputStream(outToServer);

			pstr = Integer.toString(p);
			out.writeUTF(pstr); // Sending p

			gstr = Integer.toString(g);
			out.writeUTF(gstr); // Sending g

			double A = ((Math.pow(g, a)) % p); // calculation of A
			Astr = Double.toString(A);
			out.writeUTF(Astr); // Sending A

			System.out.println("From Client : Private Key = " + a); // Client's Private Key

			DataInputStream in = new DataInputStream(s.getInputStream()); // Accepts the data

			serverB = Double.parseDouble(in.readUTF());
			System.out.println("From Server : Public Key = " + serverB);

			Adash = ((Math.pow(serverB, a)) % p); // calculation of Adash

			System.out.println("Secret Key to perform Symmetric Encryption using Diffie Hellman = " + Adash);

			Blowfish blowfish = new Blowfish(Adash);

			System.out.println(
					"\n\nSecret Key was sent, now the conversation can start between the client and the server\n\n");

			// Sending encrypted messages to the server and decrypting the ciphertext
			// received from the server
			dos = new DataOutputStream(s.getOutputStream()); // to send data to the server

			br = new BufferedReader(new InputStreamReader(s.getInputStream())); // to read data coming from the server

			kb = new BufferedReader(new InputStreamReader(System.in));
			String str, str1;

			while (!(str = kb.readLine()).equals("exit")) // repeat as long as exit is not typed at client
			{
				String ciphertext = blowfish.convertPlaintextToCiphertext(str); // str is the plaintext to be sent

				System.out.println("\nPlaintext is: " + str + "\nThe Ciphertext sent is: " + ciphertext + "\n");
				dos.writeBytes(ciphertext + "\n"); // send to the server
				str1 = br.readLine(); // receive from the server str1 is the ciphertext
				String plaintextreceived = blowfish.convertCiphertextToPlaintext(str1);
				System.out.println(
						"\nCiphertext received is: " + str1 + "\nCorresponds to the Plaintext: " + plaintextreceived
								+ "\n");
			}

		} catch (Exception e) {
			System.out.println("Exception " + e.getMessage());
			e.printStackTrace();
		} finally {
			// close connection.
			dos.close();
			br.close();
			kb.close();
			s.close();
		}
	}
}
