use ark_ec::PairingEngine;
use ark_poly::{univariate::DensePolynomial, UVPolynomial, Polynomial};
use ark_poly_commit::kzg10::{KZG10, Powers};
use ark_std::rand::{rngs::StdRng, SeedableRng};

fn main() {
    // カーブとしてBLS12-381を使用
    type E = ark_bls12_381::Bls12_381;
    type P = DensePolynomial<<E as PairingEngine>::Fr>;

    // 秘密鍵と公開鍵の生成
    let rng = &mut StdRng::from_seed([0u8; 32]);
    let max_degree = 4;
    let universal_params = KZG10::<E, P>::setup(max_degree, false, rng).unwrap();

    // コミッターキーと検証キーを作成
    let committer_key = &universal_params.powers_of_g;
    let verifier_key = ark_poly_commit::kzg10::VerifierKey {
        g: universal_params.powers_of_g[0],
        gamma_g: universal_params.powers_of_gamma_g[&0],
        h: universal_params.h,
        beta_h: universal_params.beta_h,
        prepared_h: universal_params.prepared_h.clone(),
        prepared_beta_h: universal_params.prepared_beta_h.clone(),
    };

    // 多項式の定義
    let poly = P::from_coefficients_vec(vec![
        <E as PairingEngine>::Fr::from(-60i32),
        <E as PairingEngine>::Fr::from(114i32),
        <E as PairingEngine>::Fr::from(-19i32),
    ]);

    println!("Polynomial: {:?}", poly);

    // 多項式のコミットメントを生成
    let powers_of_g_vec = (0..=poly.degree()).map(|i| committer_key[i as usize].clone()).collect::<Vec<_>>();
    let committer_key_powers = Powers::<'_, E> {
        powers_of_g: std::borrow::Cow::Borrowed(powers_of_g_vec.as_slice()),
        powers_of_gamma_g: std::borrow::Cow::Borrowed(&[]), 
    };

    let (commitment, _) = KZG10::<E, P>::commit(&committer_key_powers, &poly, None, Some(rng)).unwrap();

    println!("Commitment: {:?}", commitment);

    // 証明を生成
    let point = <E as PairingEngine>::Fr::from(2u32);
    let value = poly.evaluate(&point);
    assert_eq!(value, <E as PairingEngine>::Fr::from(92u32));

    println!("Point: {:?}", point);
    println!("Value: {:?}", value);

    // witness polynomialの計算
    let (_, randomness) = KZG10::<E, P>::commit(&committer_key_powers, &poly, None, Some(rng)).unwrap();
    let (witness_poly, _) = KZG10::<E, P>::compute_witness_polynomial(&poly, point, &randomness).unwrap();

    println!("Witness Polynomial: {:?}", witness_poly);

    // witness polynomialのコミットメント（Proofオブジェクト）を生成
    let (witness_commitment, _) = KZG10::<E, P>::commit(&committer_key_powers, &witness_poly, None, Some(rng)).unwrap();
    let proof = ark_poly_commit::kzg10::Proof {
        w: witness_commitment.0,
        random_v: None,
    };

    println!("Witness Commitment: {:?}", witness_commitment);
    println!("Proof: {:?}", proof);

    // 証明の検証
    let is_valid = KZG10::<E, P>::check(&verifier_key, &commitment, point, value, &proof).unwrap();
    assert!(is_valid, "Proof verification failed");

    println!("Proof verification succeeded!");
}

