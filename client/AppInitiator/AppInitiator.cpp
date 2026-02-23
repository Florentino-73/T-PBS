#include "AppInitiator.h"
#include "omp.h"
#include "GWAS.h"
#include <random>
#include <iomanip>
#include <set>
#include <cmath>

#include "benchmark.h"

timespec request_total, get_key_total, gwas_total;
extern uint32_t ENTRY_PAGE_SIZE;

uint32_t client_req_asyn_data(uint32_t max_data_id, uint32_t data_num, bool GWASflag){
	uint32_t req_type = 3;
	
	std::random_device rd;
	std::mt19937 gen(rd());
	std::normal_distribution<double> budget_dist(1.0, 0.5); // Mean 1.0, StdDev 0.5

    // Zipfian Distribution Setup
    double zipf_a = 0.5;
    std::vector<double> zipf_probs(max_data_id);
    double zipf_sum = 0.0;
    for (uint32_t i = 0; i < max_data_id; ++i) {
        zipf_probs[i] = 1.0 / std::pow(i + 1, zipf_a);
        zipf_sum += zipf_probs[i];
    }
    std::discrete_distribution<> zipf_dist(zipf_probs.begin(), zipf_probs.end());

	try{ // for each batch, generate an executor;
		GWAS_EXECUTOR exe(GWASflag); 
		std::vector<uint32_t> validDataId;

		// Loop for data_num requests (e.g., 100 requests)
		for (int i = 0; i < data_num; i++) {
			// 1. Generate Budget
			double budget_val = budget_dist(gen);
			if (budget_val < 0.01) budget_val = 0.01; // Minimum budget
			uint32_t request_budget = (uint32_t)(budget_val * 1000000);

			// 2. Generate 10 IDs using Zipfian distribution
			std::vector<uint32_t> tmp_vec;
			int items_per_req = 10;
            
            // Fix: limit items_per_req to max_data_id to avoid infinite loop
            int max_items = std::min((uint32_t)items_per_req, max_data_id);
            
            // Use a set to avoid duplicates in a single request
            std::set<uint32_t> selected_ids;
            while (selected_ids.size() < (size_t)max_items) {
                uint32_t id = zipf_dist(gen) + 1; // 1-based index
                if (id > max_data_id) id = max_data_id;
                selected_ids.insert(id);
            }
            
            for (uint32_t id : selected_ids) {
                tmp_vec.push_back(id);
            }

			// 3. Send Request
			char *secure_resp;
			uint32_t secure_resp_size;
			uint32_t ret_status = exe.req_wrapper_and_send((uint32_t)i, tmp_vec, request_budget, &secure_resp, &secure_resp_size, req_type);
			
			if (ret_status != 0) {
				printf("req wrapper and send cannot get info, ret value is 0x%x\n", ret_status);
				continue;
			}

			// 4. Handle Response
			if (req_type == 3) { // client request asyn batch
				uint32_t batch_id, encrypted_size;
				secure_message_t *encrypted_key;
				memcpy(&batch_id, secure_resp, sizeof(uint32_t));

				ret_status = exe.client_update_hash_then_get_key(batch_id, (uint32_t)i, &encrypted_key, &encrypted_size);
				if (ret_status != SUCCESS) {
					LOG(ERROR)<<"SOME data not get key success";
					continue;
				}
				
				validDataId.insert(validDataId.end(), tmp_vec.begin(), tmp_vec.end());

				if (GWASflag) ret_status = exe.add_key(encrypted_key, encrypted_size);
				free(encrypted_key);
			}
			free(secure_resp);
			
			LOG(INFO) << "Request " << i << " sent. Budget: " << request_budget << ", Page: " << (uint32_t)i;
		}

		if (GWASflag) 
		{
			for (uint32_t i=0; i<validDataId.size(); i++)
			{
				uint32_t ret_status = exe.run_gwas(validDataId[i]);
				if (ret_status != 0){
					printf("ret status is: 0x%x", ret_status);
				}
			}
		}
		
	}catch (uint32_t &e)
	{
		printf("ERROR INIT EXE: 0x%x.\n", e);
		return EXECUTOR_CREATE_ERROR;
	}

	return SUCCESS;
}


uint32_t split_ids(uint32_t data_num, uint32_t *data_ids, std::map<uint32_t, std::vector<uint32_t>* > &page_map){
	// std::map<uint32_t, std::vector<uint32_t>* >page_map;
	std::vector<uint32_t> *vec_ids;

	for (int i=0; i<data_num; i++){
		uint32_t id = data_ids[i];
		uint32_t page_id = id / ENTRY_PAGE_SIZE;

		std::map<uint32_t, std::vector<uint32_t>*>::iterator it=page_map.find(page_id);
		if (it != page_map.end()){
			vec_ids = it->second;
			vec_ids->push_back(id);
		}
		else{
			vec_ids = new std::vector<uint32_t>();
			vec_ids->push_back(id);
			// page_map.insert(make_pair<uint32_t, std::vector<uint32_t>*>(page_id, vec_ids));
			page_map[page_id] = vec_ids;
		}
	}
    return SUCCESS;
}


uint32_t get_file_req(uint32_t id){
	FIFO_MSG *req = (FIFO_MSG*)malloc(sizeof(FIFO_MSG));
	if (!req) return MALLOC_ERROR;

	req->header.size = id;
	req->header.type = FIFO_FILE_REQ;

	// Get filename
	char *filename;
	if (get_encrypted_filename(id, &filename) != 0) {
		free(req);
		return INVALID_SESSION;
	}

	FIFO_MSG *response = NULL;
	size_t response_size = 0;
	int ret = client_get_file(req, sizeof(FIFO_MSG), filename, &response, &response_size);
	
	if (response) {
		free(response);
	}
	free(filename);
	free(req);
	
	if (ret != 0) return INVALID_SESSION;

	return SUCCESS;
}