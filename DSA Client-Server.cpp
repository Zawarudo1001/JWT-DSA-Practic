#include <iostream>
#include "UdpClientSocket.hpp"
#include "UdpServerSocket.hpp"
#include <string>
#include <cryptopp-master\cryptlib.h>
#include <cryptopp-master\sha.h>
#include <cryptopp-master\hex.h>
#include <cryptopp-master\dsa.h>
#include <cryptopp-master\osrng.h>
#include "Sniffer.h"
#include <chrono>
#include <thread>
#include "cryptopp-master\base64.h"
#include "cryptopp-master\files.h"
#include <stdio.h>

#include <jwt-cpp/jwt.h>


using namespace std;
using namespace CryptoPP;


std::string DSA_createSignature(std::string message, AutoSeededRandomPool &prng, CryptoPP::DL_Keys_DSA::PrivateKey privateKey) {
	std::string signature;
	std::string output;

	CryptoPP::DSA::Signer signer(privateKey);
	CryptoPP::StringSource(message, true,
		new CryptoPP::SignerFilter(prng, signer,
			new CryptoPP::StringSink(signature)
		) //SignerFilter
	); //StringSource

	CryptoPP::StringSource(signature, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(output)
		) //HexEncoder
	); //StringSource
	return output;
}


bool DSA_verifySignature(std::string message, std::string signature, DL_Keys_DSA::PublicKey publicKey) {
	std::string decoded;
	std::string output;
	bool result = false;

	CryptoPP::StringSource(signature, true,
		new CryptoPP::HexDecoder(
			new CryptoPP::StringSink(decoded)
		) //StringSink
	); //StringSource

	CryptoPP::DSA::Verifier verifier(publicKey);
	CryptoPP::StringSource(message + decoded, true,
		new CryptoPP::SignatureVerificationFilter(
			verifier,
			new CryptoPP::ArraySink((CryptoPP::byte*) &result, sizeof(result)),
			CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_END
		) //SignatureVerificationFilter
	); //StringSource
	return result;
}


void Client_Handle(int SecureParameter) {
	unsigned char increment = 0;
	UdpClientSocket client("192.168.194.1", 10001);
	string client_message;
	string signature = "";
	AutoSeededRandomPool prng;
	CryptoPP::DSA::PrivateKey privateKey;
	privateKey.GenerateRandomWithKeySize(prng, 2048);
	CryptoPP::DSA::PublicKey publicKey;
	publicKey.AssignFrom(privateKey);
	Base64Encoder pubkeysink(new FileSink("pubkey.txt"));
	publicKey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();

	while (true) {

		if (SecureParameter == 0) {
			client_message = "Hello from client!";
			client_message += increment;
			++increment;
		}
		if (SecureParameter == 1) {
			string random_message;
			for (int8_t i = 0; i < 10; i++) random_message += (char)rand();
			client_message = random_message;
		}
		if (SecureParameter == 2) {
			client_message = "Hello from client!";
		}
		if (signature.length() == 0) signature = DSA_createSignature(client_message, prng, privateKey);

		if (signature.length() > 0) {

			if (SecureParameter != 2) signature = DSA_createSignature(client_message, prng, privateKey);
		}
		
		string data_to_send = signature + client_message;

		char* buffer = new char[signature.length() + client_message.length()];
		memcpy(buffer, signature.c_str(), signature.length());
		memcpy(buffer + signature.length(), client_message.c_str(), client_message.length());

		client.sendData(buffer, signature.length() + client_message.length());

		cout << "Client:: ";
		cout << signature.length() + client_message.length() << " bytes were sent to server" << endl;
		this_thread::sleep_for(chrono::milliseconds(1000));
		delete[] buffer;
	}
}


void Server_Handle(int SecureParameter) {
	UdpServerSocket server(10001);
	char buffer[65536];
	int increment = 0;
	int sig_correct;
	vector<string> used;

	while (true) {
		sig_correct = 1;
		int recv_bytes = server.receiveData(buffer, 65536);
		cout << "Server:: ";
		cout << "recieved " << recv_bytes << " bytes" << endl;
		//64 bytes signature + message
		if (recv_bytes == 0) continue;

		CryptoPP::ByteQueue bytes;
		FileSource file("pubkey.txt", true, new Base64Decoder);
		file.TransferTo(bytes);
		bytes.MessageEnd();
		CryptoPP::DSA::PublicKey publicKey;
		publicKey.Load(bytes);


		string signature(buffer, 112);
		string message(buffer + 112, recv_bytes - 112);

		string final_message = message;

		
		cout << signature << endl;
		cout << final_message << endl;

		cout << "Server:: ";
		bool sig = DSA_verifySignature(message, signature, publicKey);
		if (sig) sig_correct *= 1;

		if (SecureParameter == 1) {
			if (find(used.begin(), used.end(), final_message) != used.end()) sig_correct *= 0;
			else if (sig) used.push_back(final_message);
		}

		if (SecureParameter == 0 and final_message.back() < increment ) sig_correct *= 0;
		if (sig and SecureParameter == 0) ++increment;


		if (sig_correct) cout << "Signature is correct" << endl;
		if (!sig_correct) cout << "WRONG SIGNATURE!" << endl;
		cout << "\n\n\n";

		this_thread::sleep_for(chrono::milliseconds(1));
	}
}


void Penetrate_Handle() {
	UdpClientSocket client("192.168.194.1", 10001);
	string client_message;
	string signature;

	while (true) {

		cout << "Enter corrupted message with signature to send it to the server..." << endl;
		getline(cin, client_message);
		getline(cin, signature);

		string data_to_send = signature + client_message;

		char* buffer = new char[signature.length() + client_message.length()];
		memcpy(buffer, signature.c_str(), signature.length());
		memcpy(buffer + signature.length(), client_message.c_str(), client_message.length());

		client.sendData(buffer, signature.length() + client_message.length());
		this_thread::sleep_for(chrono::milliseconds(1000));
		delete[] buffer;
	}
}

int main(int argc, char **argv)
{
	auto token = jwt::create()
		.set_issuer("auth0")
		.set_type("JWS")
		.set_payload_claim("sample", jwt::claim(std::string("test")))
		.sign(jwt::algorithm::hs512{ "secret" });


	auto decoded = jwt::decode(token);

	for (auto& e : decoded.get_payload_claims())
		std::cout << e.first << " = " << e.second.to_json() << std::endl;


	auto verifier = jwt::verify()
		.allow_algorithm(jwt::algorithm::hs512{ "secret" })
		.with_issuer("auth0");

	verifier.verify(decoded);


	cout << "STARTING UP THE SIMULATION STAND..." << endl;
	if (argc == 3) {
		if (strcmp(argv[1], "-s") == 0) Server_Handle((int)*argv[2] - int('0'));
		if (strcmp(argv[1], "-c") == 0) Client_Handle((int)*argv[2] - int('0'));
	}
	if (argc == 2 and strcmp(argv[1], "-a") == 0) Sniffer_Handle();
	if (argc == 2 and strcmp(argv[1], "-p") == 0) Penetrate_Handle();

}
