"use strict";


class SHAsh {
	constructor() {
		this.SHA256_h = [
			0x6a09e667,
			0xbb67ae85,
			0x3c6ef372,
			0xa54ff53a,
			0x510e527f,
			0x9b05688c,
			0x1f83d9ab,
			0x5be0cd19,
			];

		this.SHA256_k = [
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
			];
	}

	SHA256(message)
	{
		let H = new Uint32Array(this.SHA256_h);

		let len = message.length * 8;
		message = message + String.fromCharCode(0x80);
		let bits = message.length * 8;
		let padding = 448 - (bits % 512);
		if (padding < 0) {
			padding += 512;
		}
		let messageByte = new Uint8Array(new Array(message.length + padding / 8 + 8));
		for (let i = 0; i < message.length; ++i) {
			messageByte[i] = message.charCodeAt(i);
		}
		for (let i = message.length; i < messageByte.length; ++i) {
			messageByte[i] = 0;
		}
		for (let i = 0; i < 4; ++i) { // not 64bit big integer
			messageByte[messageByte.length - 1 - i] = (len >> (i * 8)) & 0xff;
		}
		// Start processing on each 512-bit chunks
		for (let chunk = 0; chunk < Math.ceil((bits + padding + 64) / 512); ++chunk) {
			// initiailze
			let w = new Uint32Array(new Array(64));
			for (let i = 0; i < 16; ++i) {
				w[i] =
				    ((messageByte[64 * chunk + 4 * i + 0] << 24) & 0xff000000) |
				    ((messageByte[64 * chunk + 4 * i + 1] << 16) & 0x00ff0000) |
				    ((messageByte[64 * chunk + 4 * i + 2] <<  8) & 0x0000ff00) |
				    ((messageByte[64 * chunk + 4 * i + 3]      ) & 0x000000ff);
			}
			for (let i = 16; i < 64; ++i) {
				let s0 =
				    (((w[i - 15] << (32 - 7)) & 0xfe000000) | ((w[i - 15] >> 7) & 0x01ffffff)) ^
				    (((w[i - 15] << (32 - 18)) & 0xffffc000) | ((w[i - 15] >> 18) & 0x00003fff)) ^
				    ((w[i - 15] >> 3) & 0x1fffffff);
				let s1 =
				    (((w[i - 2] << (32 - 17)) & 0xffff8000) | ((w[i - 2] >> 17) & 0x00007fff)) ^
				    (((w[i - 2] << (32 - 19)) & 0xffffe000) | ((w[i - 2] >> 19) & 0x00001fff)) ^
				    ((w[i - 2] >> 10) & 0x003fffff);
				w[i] = w[i - 16] + s0 + w[i-7] + s1;
			}
			let a = H[0];
			let b = H[1];
			let c = H[2];
			let d = H[3];
			let e = H[4];
			let f = H[5];
			let g = H[6];
			let h = H[7];

			for (let i = 0; i < 64; ++i) {
				let S1 =
				    (((e << (32 - 6)) & 0xfc000000) | ((e >> 6) & 0x03ffffff)) ^
				    (((e << (32 - 11)) & 0xffe00000) | ((e >> 11) & 0x001fffff)) ^
				    (((e << (32 - 25)) & 0xffffff80) | ((e >> 25) & 0x0000007f));
				let ch = (e & f) ^ (~e & g);
				let temp1 = h + S1 + ch + this.SHA256_k[i] + w[i];
				let S0 =
				    (((a << (32 - 2)) & 0xc0000000) | ((a >> 2) & 0x3fffffff)) ^
				    (((a << (32 - 13)) & 0xfff80000) | ((a >> 13) & 0x0007ffff)) ^
				    (((a << (32 - 22)) & 0xfffffc00) | ((a >> 22) & 0x000003ff));
				let maj = (a & b) ^ (a & c) ^ (b & c);
				let temp2 = S0 + maj;
				h = g;
				g = f;
				f = e;
				e = d + temp1;
				d = c;
				c = b;
				b = a;
				a = temp1 + temp2;
			}
			H[0] = H[0] + a;
			H[1] = H[1] + b;
			H[2] = H[2] + c;
			H[3] = H[3] + d;
			H[4] = H[4] + e;
			H[5] = H[5] + f;
			H[6] = H[6] + g;
			H[7] = H[7] + h;
		}

		let hash = '';
		for (let i = 0; i < 8; ++i) {
			let tmp;
			tmp = (H[i] >> 24) & 0xff;
			hash += ((tmp > 0x0f) ? '' : '0') + tmp.toString(16);
			tmp = (H[i] >> 16) & 0xff;
			hash += ((tmp > 0x0f) ? '' : '0') + tmp.toString(16);
			tmp = (H[i] >> 8) & 0xff;
			hash += ((tmp > 0x0f) ? '' : '0') + tmp.toString(16);
			tmp = H[i] & 0xff;
			hash += ((tmp > 0x0f) ? '' : '0') + tmp.toString(16);
		}
		return hash;
	}
}

