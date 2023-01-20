import java.io.*;
import java.net.*;

class Server {
	static int port = 10000;
	static int b = 3; // Server Key
	static double clientP, clientG, clientA, B, Bdash;
	static String Bstr;
	static PrintStream ps;
	static BufferedReader br, kb;
	static Socket s;
	static ServerSocket ss;

	public static void main(String args[])
			throws Exception {
		try {

			System.out.println("Server started at port " + Integer.toString(port));

			ss = new ServerSocket(port); // Create server Socket
			System.out.println("Waiting for client on port " + ss.getLocalPort() + "...");
			s = ss.accept(); // connect it to client socket
			System.out.println("Connection established");

			// Secret Key Exchange (Diffie-Hellman)
			System.out.println("From Server : Private Key = " + b);

			DataInputStream in = new DataInputStream(s.getInputStream()); // Accepts the data from client

			clientP = Integer.parseInt(in.readUTF()); // to accept p
			System.out.println("From Client : P = " + clientP);

			clientG = Integer.parseInt(in.readUTF()); // to accept g
			System.out.println("From Client : G = " + clientG);

			clientA = Double.parseDouble(in.readUTF()); // to accept A
			System.out.println("From Client : Public Key = " + clientA);

			B = ((Math.pow(clientG, b)) % clientP); // calculation of B
			Bstr = Double.toString(B);

			// Sends data to client
			OutputStream outToclient = s.getOutputStream();
			DataOutputStream out = new DataOutputStream(outToclient);

			out.writeUTF(Bstr); // Sending B

			Bdash = ((Math.pow(clientA, b)) % clientP); // calculation of Bdash

			System.out.println("Secret Key to perform Symmetric Encryption using Diffie Hellman = " + Bdash);

			Blowfish blowfish = new Blowfish(Bdash);

			System.out.println(
					"\n\nSecret Key was sent, now the conversation can start between the client and the server\n\n");

			// Sending encrypted messages to the client and decrypting the ciphertext
			// received from the client
			ps = new PrintStream(s.getOutputStream()); // to send data to the client
			br = new BufferedReader(new InputStreamReader(s.getInputStream())); // to read data coming from the client
			kb = new BufferedReader(new InputStreamReader(System.in)); // to read data from the keyboard

			while (true) {
				String str, str1;
				// repeat as long as the client does not send a null string
				while ((str = br.readLine()) != null) // read from client
				{
					String plaintextreceived = blowfish.convertCiphertextToPlaintext(str);
					System.out.println(
							"\nCiphertext received is: " + str + "\nCorresponds to the Plaintext: " + plaintextreceived
									+ "\n");
					str1 = kb.readLine();
					String ciphertext = blowfish.convertPlaintextToCiphertext(str1);
					System.out.println("\nPlaintext is: " + str1 + "\nThe Ciphertext sent is: " + ciphertext + "\n");

					ps.println(ciphertext); // send to client
				}
			}
		} catch (SocketTimeoutException s) {
			System.out.println("Socket timed out!");
		} catch (IOException e) {
			System.out.println("Exception " + e.getMessage());
		} finally {
			// close connection
			ps.close();
			br.close();
			kb.close();
			ss.close();
			s.close();
			System.exit(0); // terminate application
		}
	}
}
