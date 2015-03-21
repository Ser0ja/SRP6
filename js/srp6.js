var rsp6 = function(){
	/*----- CONSTANTS -----*/
	var I = '', 	//User name
		p = '', 	//Password

		s = '', 	//Salt
		v = '', 	//Validation sum g ^ x % N


		N = '', 	//Safe prime

		a = '', 	//Random number

		k = '', 	//Multiplying constant H( N, g )
		g = '', 	//Modulus generator
		x = '', 	//Hash-salted password H( s, p )

		u = '', 	//Handshake fingerprint H( A, B )

		K = '', 	//Client session key H(S)

		A = '', 	//Mixed parties keys(Diffie-Helman) g % N
		B = '', 	//Mixed parties keys(Diffie-Helman) k * v + g ^ b % N

		Sc = '', 	//((B - k * ( g ^ x % N )) ^ ( a + u * x )) % N
		Ss = '', 	//(( A * ( v ^ u % N )) ^ B ) % N

		Mc = '', 	//Client confirmation message H( H(N) XOR H(g), H(I), S, A, B, K )

		Rc = '', 	//Client response H(A, Mc, Kc)
		Rs = ''; 	//Server response H(A, Ms, Ks)

	/*----- CONSTANTS -----*/
	
}