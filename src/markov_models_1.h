/**
*
*    SLIPS - Stratosphere Linux IPS
*
*    Author: Sebastian Garcia.
*    Email : eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz
*
*    Stratosphere IPS, a behavioral-based intrusion detection and prevention
*    system that uses machine learning algorithms to detect malicious behaviors
*    Website : https://stratosphereips.org/
*
*    libSlips - CPP Implementation of Stratosphere IPS
*    markov_models_1.h is written by Sachin Vernekar (savernek@cisco.com)
*
*    Copyright (C) 2016, Cisco Systems Inc.
*
*    This library is free software; you can redistribute it and/or
*    modify it under the terms of the GNU Lesser General Public
*    License as published by the Free Software Foundation; either
*    version 2.1 of the License, or (at your option) any later version.
*
*    This library is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*    Lesser General Public License for more details.
*
*    You should have received a copy of the GNU Lesser General Public
*    License along with this library; if not, write to the Free Software
*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*
**/
#ifndef MARKOV_MODELS_1_H
#define MARKOV_MODELS_1_H

#include "markov_chains.h"
#include "util.h"

class Model
{
private:
    int id;
    double self_probability;
    std::string label;
    // To store when this model had the best match. Later use to cut the state
    int best_matching_len;
    double threshold;
    bool model_state;
    std::string state;
    std::string protocol;

public:
    std::map<char, double> init_vector;
    Matrix matrix;
    bool matched;
    Model(int id);
    Model();
    void set_model_state(bool model_state);
    bool get_model_state();
    void clear();
    void set_best_model_matching_len(int statelen);
    int get_best_model_matching_len();
    bool create(std::string state);
    double compute_probability(std::string state);
    void set_state(std::string state);
    std::string get_state();
    int get_id();
    void set_init_vector(std::map<char, double> vector);
    std::map<char, double> get_init_vector();
    void set_matrix(Matrix matrix) ;
    Matrix get_matrix();
    void set_self_probability(double prob);
    double get_self_probability();
    void set_protocol(std::string protocol);
    std::string get_protocol();
    void set_label(std::string label);
    std::string get_label() ;
    void set_threshold(double threshold);
    double get_threshold();
};


class MarkovModelsDetection
{
    //Class that do all the detection using markov models
private:
    int id;
    std::vector<Model> models;
    int verbose;
    const size_t num_patterns = 54;
    const static std::string basic_patterns[];

public:
    MarkovModelsDetection();
    bool is_periodic(std::string state);
    void set_model_to_detect(const char* file);
    DetectionInfo detect(Tuple tuple, int verbose) throw(int);
};
#endif
