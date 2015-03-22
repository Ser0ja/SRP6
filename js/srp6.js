var rsp6 = (function(){
	/*----- VARIABLES -----*/
	var I = 0, 	//User name
		p = 0, 	//Password
		s = 0, 	//Salt

		v = 0, 	//Validation sum g ^ x % N


		N = parseInt('EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3' 16), 	//Safe prime

		a = 0, 	//Random number

		k = 0, 	//Multiplying constant H( N, g )
		g = 2, 	//Modulus generator
		x = 0, 	//Hash-salted password H( s, p )

		u = 0, 	//Handshake fingerprint H( A, B )


		A = 0, 	//Mixed parties keys(Diffie-Helman) g % N
		B = 0, 	//Mixed parties keys(Diffie-Helman) k * v + g ^ b % N

		S = 0, 	//Session Id((B - k * ( g ^ x % N )) ^ ( a + u * x )) % N
		K = 0, 	//Client session key H(S)

		Mc = 0, //Client confirmation message H( H(N) XOR H(g), H(I), S, A, B, K )

		Rc = 0, //Client response H(A, Mc, Kc)
		Rs = 0, //Server response H(A, Ms, Ks)

	/*----- VARIABLES END -----*/

	/*----- METHODS -----*/
		calc = {

			//Hash function
			H: function(){
				if(!arguments.length === 0){
					var concat = 0;
					for(var i = 0; i < arguments.length; i++){
						concat = concat + arguments[i].toString(16);
					}
					return CryptoJS.SHA512(concat);

				}
				return undefined;
			},

			PRNG: function(){
				var randomWords;
				if (window.crypto && window.crypto.getRandomValues) {
					//Use broser 
					randomWords = new Int32Array(wordCount);
					window.crypto.getRandomValues(randomWords);

				}else if (window.msCrypto && window.msCrypto.getRandomValues) {

					randomWords = new Int32Array(wordCount);
					window.msCrypto.getRandomValues(randomWords);

				}else {

				}
			},
		
			v: function(){
				//Validation sum g ^ x % N
				return Math.pow(g, x) % N;
			},
			
			A: function(){ 
				//Mixed parties keys(Diffie-Helman) g % N
				return g % N;
			},
			
			B: function(){ 
				//Mixed parties keys(Diffie-Helman) k * v + g ^ b % N
				return k * v + Math.pow(g, b) % N;
			},

			u: function(){
				return this.H(A, B);
			},

			x: function(){
				return this.H(s, p);
			},

			S: function(){
				//Session sum
				return ( Math.pow( ( B - k * ( Math.pow(g, x) % N )), a + u*x ) ) % N;
			},
			
			K: function(){
				//Session key
				return this.H(S)
			},

			m: function(){
				return this.H( parseInt(this.H(N), 16) ^ parseInt(this.H(g), 16), this.H(I), S, A, B, K);
			},

			R: function(){
				return H(A, Mc, K);
			}
		}
	/*----- METHODS END -----*/

}())