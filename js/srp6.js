var rsp6 = (function(){
	/*----- VARIABLES -----*/
	var I = 0, 	//User name
		p = 0, 	//Password
		s = 0, 	//Salt

		v = 0, 	//Validation sum g ^ x % N


		N = 0, 	//Safe prime

		a = 0, 	//Random number

		k = 0, 	//Multiplying constant H( N, g )
		g = 0, 	//Modulus generator
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