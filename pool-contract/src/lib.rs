pub mod verifier;

use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::TreeMap;
use near_sdk::{env, near_bindgen, json_types::Base64VecU8};
use verifier::{alt_bn128_groth16verify, Fr, VK, Proof};


#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[near_bindgen]
#[derive(Default, BorshDeserialize, BorshSerialize)]
pub struct Groth16Verifier {
    pub n_calls:u64,
    pub res_calls: TreeMap<u64,bool>
}


#[near_bindgen]
impl Groth16Verifier {
    pub fn n_calls(&self) -> u64 {
        self.n_calls
    }

    pub fn get_call(&self, n:u64) -> Option<bool> {
        self.res_calls.get(&n)
    }

    pub fn groth16verify(&self, vk: Base64VecU8, proof:Base64VecU8, input:Base64VecU8) -> bool {
        let vk = VK::deserialize(&mut &Vec::<u8>::from(vk)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize vk."));
        let proof = Proof::deserialize(&mut &Vec::<u8>::from(proof)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize proof."));
        let input = Vec::<Fr>::deserialize(&mut &Vec::<u8>::from(input)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize input."));
        alt_bn128_groth16verify(vk, proof, input)
    }

    pub fn groth16verify_native(&self, vk: Base64VecU8, proof:Base64VecU8, input:Base64VecU8) -> u64 {
        let vk = VK::deserialize(&mut &Vec::<u8>::from(vk)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize vk."));
        let proof = Proof::deserialize(&mut &Vec::<u8>::from(proof)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize proof."));
        let input = Vec::<Fr>::deserialize(&mut &Vec::<u8>::from(input)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize input."));
        let res = verifier::native::alt_bn128_groth16verify_native(vk, proof, input);
        if res {
            env::used_gas()
        } else {
            0
        }
    }

    pub fn groth16verify_log(&mut self, vk: Base64VecU8, proof:Base64VecU8, input:Base64VecU8) -> u64 {
        let vk = VK::deserialize(&mut &Vec::<u8>::from(vk)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize vk."));
        let proof = Proof::deserialize(&mut &Vec::<u8>::from(proof)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize proof."));
        let input = Vec::<Fr>::deserialize(&mut &Vec::<u8>::from(input)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize input."));
        let res = alt_bn128_groth16verify(vk, proof, input);
        self.res_calls.insert(&self.n_calls, &res);
        self.n_calls+=1;
        env::used_gas()
    }

    pub fn groth16verify_log_native(&mut self, vk: Base64VecU8, proof:Base64VecU8, input:Base64VecU8) -> u64{
        let vk = VK::deserialize(&mut &Vec::<u8>::from(vk)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize vk."));
        let proof = Proof::deserialize(&mut &Vec::<u8>::from(proof)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize proof."));
        let input = Vec::<Fr>::deserialize(&mut &Vec::<u8>::from(input)[..]).unwrap_or_else(|_| env::panic(b"Cannot deserialize input."));
        let res = verifier::native::alt_bn128_groth16verify_native(vk, proof, input);
        self.res_calls.insert(&self.n_calls, &res);
        self.n_calls+=1;
        env::used_gas()
    }    

}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::MockedBlockchain;
    use near_sdk::{testing_env, VMContext};
    use serde::{Serialize, Deserialize};
    use serde_json;
    use verifier::{Fq2, G2};

    pub trait RevOrdering {
        fn rev_ordering(&mut self);
    }
    
    impl RevOrdering for Fq2 {
        fn rev_ordering(&mut self) {
            *self = Self(self.1, self.0)
        }
    }
    
    
    impl RevOrdering for G2 {
        fn rev_ordering(&mut self) {
            self.0.rev_ordering();
            self.1.rev_ordering();
        }
    }
    
    
    impl RevOrdering for VK {
        fn rev_ordering(&mut self) {
            self.beta_g2.rev_ordering();
            self.gamma_g2.rev_ordering();
            self.delta_g2.rev_ordering();
        }
    }
    
    impl RevOrdering for Proof {
        fn rev_ordering(&mut self) {
            self.b.rev_ordering();
        }
    }
    #[derive(Clone, Serialize, Deserialize)]
    struct Params{
        vk:Base64VecU8,
        proof:Base64VecU8,
        input:Base64VecU8
    }

    #[test]
    fn test_verifier() {
        let vk_data = r#"{"alpha_g1":["7519284530658385413481729597245720500030404990462629904897898136763311124168","7759305346990060398806855044079194419731758745769222108787862678726666900220"],"beta_g2":[["1176649506803683766765422712992584640052508597600331524207624969164785648052","12658514753455364255847347356482838872202464563210394015283712905609817617215"],["5101165399365558344990622388380303844882446238022873489370271119435994448723","21636711779296379288552588423407018283375205758461617755430164958214291425324"]],"gamma_g2":[["9563259163523751010149091049096621603384601617762202898305068080460508703482","18614172729111398410642152943077024203312410577460779291567515130504309581422"],["12621444442673662801320090583641606322810680442819355704097044349429764048796","17216172718858700295335335730679086396625358808428380281751049509583791629262"]],"delta_g2":[["19725912176908845463228350949600426717278140749628152615121896685037506347011","17691763529654559336605901395565305758251561614530184689342930207658179614206"],["20238568526203996774716543421041972327669035296195845273002576718877215923164","15710570036806237863872618522246158637753680141692137028567816236766869162809"]],"ic":[["3964469773568119779052821042808454784223031204987385635064017202325906327385","2073371815659986312890584980465551647231124680817898465902507207756050662914"],["4200764591093886258865897762205005440549504077177167612462074109108510041154","8210162094715128697891465727401339441835903868694705140685126081493645419200"],["11199418528656095984467893172993547135742541654865846474409172511469530639430","3372662532236438142930946469282900573364450071306042743217169532251229727789"],["10558449468201057926921669993065084153745189931137637082603458431351529160370","15322117100181648633046563406466145990156007727196599836948526707694418130332"]]}"#;
        let proof_data = r#"{"a":["21043037212023412872652135275628577069606762281947467181607878147879655369793","11391638837027929377007053995004384561704549985652608308694846372242854188373"],"b":[["14717031433646916944179522170475238687961921977877202038288877044720520170335","11367876662147374721764202840481604860490092766353562008338272528492341756873"],["8547188232587596773995555326777331488318150619810926443278938036838567497339","2288215547019467674158223485296290725771964506608322019365849703537867366708"]],"c":["13775297247810760300790651473298540941951313217152384330093971036306580680406","8848858450888865898290411836574982432732750169946139830040805919604759169863"]}"#;
        let input_data = r#"["6312388174271946628009376311828913110600126535927993427049310256231803794882","19151878342329385484801902211804929466921026268651676084442650160555830671451","16960269216762094114673992166783997514673209322789784124347418911889771148796"]"#;
        let mut vk : VK = serde_json::from_str(vk_data).unwrap();
        vk.rev_ordering();
        let mut proof : Proof = serde_json::from_str(proof_data).unwrap();
        proof.rev_ordering();
        let input : Vec<Fr> = serde_json::from_str(input_data).unwrap();

        let params = Params {
            vk: Base64VecU8(vk.try_to_vec().unwrap()),
            proof: Base64VecU8(proof.try_to_vec().unwrap()),
            input: Base64VecU8(input.try_to_vec().unwrap())
        };

        let context = get_context(vec![], true);
        println!("{}", serde_json::to_string(&params).unwrap());
        testing_env!(context);
        let contract = Groth16Verifier::default();
        assert!(contract.groth16verify(params.vk, params.proof, params.input), "Groth16 verify should be true");
    }

    #[test]
    fn test_verifier_false() {
        let vk_data = r#"{"alpha_g1":["7519284530658385413481729597245720500030404990462629904897898136763311124168","7759305346990060398806855044079194419731758745769222108787862678726666900220"],"beta_g2":[["1176649506803683766765422712992584640052508597600331524207624969164785648052","12658514753455364255847347356482838872202464563210394015283712905609817617215"],["5101165399365558344990622388380303844882446238022873489370271119435994448723","21636711779296379288552588423407018283375205758461617755430164958214291425324"]],"gamma_g2":[["9563259163523751010149091049096621603384601617762202898305068080460508703482","18614172729111398410642152943077024203312410577460779291567515130504309581422"],["12621444442673662801320090583641606322810680442819355704097044349429764048796","17216172718858700295335335730679086396625358808428380281751049509583791629262"]],"delta_g2":[["19725912176908845463228350949600426717278140749628152615121896685037506347011","17691763529654559336605901395565305758251561614530184689342930207658179614206"],["20238568526203996774716543421041972327669035296195845273002576718877215923164","15710570036806237863872618522246158637753680141692137028567816236766869162809"]],"ic":[["3964469773568119779052821042808454784223031204987385635064017202325906327385","2073371815659986312890584980465551647231124680817898465902507207756050662914"],["4200764591093886258865897762205005440549504077177167612462074109108510041154","8210162094715128697891465727401339441835903868694705140685126081493645419200"],["11199418528656095984467893172993547135742541654865846474409172511469530639430","3372662532236438142930946469282900573364450071306042743217169532251229727789"],["10558449468201057926921669993065084153745189931137637082603458431351529160370","15322117100181648633046563406466145990156007727196599836948526707694418130332"]]}"#;
        let proof_data = r#"{"a":["21043037212023412872652135275628577069606762281947467181607878147879655369793","11391638837027929377007053995004384561704549985652608308694846372242854188373"],"b":[["14717031433646916944179522170475238687961921977877202038288877044720520170335","11367876662147374721764202840481604860490092766353562008338272528492341756873"],["8547188232587596773995555326777331488318150619810926443278938036838567497339","2288215547019467674158223485296290725771964506608322019365849703537867366708"]],"c":["13775297247810760300790651473298540941951313217152384330093971036306580680406","8848858450888865898290411836574982432732750169946139830040805919604759169863"]}"#;
        let input_data = r#"["6312388174271946628009376311828913110600126535927993427049310256231803794881","19151878342329385484801902211804929466921026268651676084442650160555830671451","16960269216762094114673992166783997514673209322789784124347418911889771148796"]"#;
        let mut vk : VK = serde_json::from_str(vk_data).unwrap();
        vk.rev_ordering();
        let mut proof : Proof = serde_json::from_str(proof_data).unwrap();
        proof.rev_ordering();
        let input : Vec<Fr> = serde_json::from_str(input_data).unwrap();

        let params = Params {
            vk: Base64VecU8(vk.try_to_vec().unwrap()),
            proof: Base64VecU8(proof.try_to_vec().unwrap()),
            input: Base64VecU8(input.try_to_vec().unwrap())
        };

        let context = get_context(vec![], true);
        println!("{}", serde_json::to_string(&params).unwrap());
        testing_env!(context);
        let contract = Groth16Verifier::default();
        assert!(!contract.groth16verify(params.vk, params.proof, params.input), "Groth16 verify should be false");
    }


    fn get_context(input: Vec<u8>, is_view: bool) -> VMContext {
        VMContext {
            current_account_id: "alice_near".to_string(),
            signer_account_id: "bob_near".to_string(),
            signer_account_pk: vec![0, 1, 2],
            predecessor_account_id: "carol_near".to_string(),
            input,
            block_index: 0,
            block_timestamp: 0,
            account_balance: 0,
            account_locked_balance: 0,
            storage_usage: 0,
            attached_deposit: 0,
            prepaid_gas: 10u64.pow(18),
            random_seed: vec![0, 1, 2],
            is_view,
            output_data_receivers: vec![],
            epoch_height: 0,
        }
    }

}
