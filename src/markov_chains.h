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
*    markov_chains.h is written by Sachin Vernekar (savernek@cisco.com)
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
#ifndef MARCOV_CHAINS_H
#define MARCOV_CHAINS_H


#include <string>
#include <map>

// Library to compute some markov chain functions for the Stratosphere Project. We created them because pykov lacked the second order markov chains
// The basic matrix object.
class Matrix
{
private:
    bool matrix_state;
public:
    std::map<char, double> init_vector;
    std::map<std::string, double> matrix;
    Matrix();
    void set_init_vector(std::map<char, double> init_vector);
    bool get_matrix_state();
    void set_matrix_state(bool maatrix_state);
    void clear();
    std::map<char, double> get_init_vector();
    void update_matrix(std::string str, double value);
    double walk_probability(std::string states) throw(int);
    void print_matrix();
};


class MarkovData
{
public:
    std::map<char, double> init_vector;
    Matrix matrix;
};

MarkovData maximum_likelihood_probabilities(std::string states, int order = 1);

#endif
