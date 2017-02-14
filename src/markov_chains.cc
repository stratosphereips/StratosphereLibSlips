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
*    markov_chains.cc is written by Sachin Vernekar (savernek@cisco.com)
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
#include <iostream>
#include <cmath>
#include <map>
#include "markov_chains.h"
#include <iterator>
#include "constants.h"

using std::cerr;
using std::cout;
using std::endl;

// Library to compute some markov chain functions for the Stratosphere Project.

// The basic matrix object.
Matrix::Matrix()
{
    matrix_state = true;
}

bool Matrix::get_matrix_state()
{
    return matrix_state;
}

void Matrix::set_matrix_state(bool matrix_state)
{
    this->matrix_state = matrix_state;
}

void Matrix::clear()
{
    matrix_state = false;
    init_vector.clear();
    matrix.clear();
}

void Matrix::set_init_vector(std::map<char, double> init_vector)
{
    this->init_vector = init_vector;
}

std::map<char, double> Matrix::get_init_vector()
{
    return init_vector;
}

void Matrix::update_matrix(std::string str, double value)
{
    matrix[str] = value;
}

double Matrix::walk_probability(std::string states) throw(int)
{
    /*
       Compute the probability of generating these states using ourselves.
       The returned value must be log.
       The main feature of this markov function is that is not trying to
       recognize each "state", it just uses each position of the vector
       given as new state. This allow us to have more complete states
       to work.
     */
    try
    {
        double cum_prob = 0.0;
        size_t index = 0;
        double prob12;
        // index should be < that len - 1 because index starts in 0,
        // and a two position vector has len 2, but the index of the last
        // position is 1.
        // The len of the states should be > 1 because a state of only
        // one char does NOT have any transition.
        while (index < states.size() - 1 && states.size() > 1)
        {
            std::string statestuple;
            statestuple.push_back(states[index]);
            statestuple.push_back(states[index+1]);
            if(matrix.find(statestuple) != matrix.end())
            {
                prob12 = log(matrix[statestuple]);
            }
            else
            {
                // The transition is not in the matrix
                cum_prob = -INFINITY;
                break;
            }
            cum_prob += prob12;
            index += 1;
        }
        return cum_prob;
    }
    catch(const std::exception &e)
    {
        cerr << "ERROR: Exception occurred in walk_probability()\n" << e.what() <<endl;
        throw(ERROR_UNEXPECTED_ERROR);
    }
    catch(...)
    {
        cerr << "ERROR: Unknown exception occurred in walk_probability()" <<endl;
        throw(ERROR_UNEXPECTED_ERROR);
    }
}

void Matrix::print_matrix() {
    for (std::map<std::string, double>::iterator it=matrix.begin(); it!=matrix.end(); ++it)
        cout << "\t\t\t\t(" <<  it->first[0] << " " << it->first[1]  << "):" << it->second <<endl;
}

MarkovData maximum_likelihood_probabilities(std::string states, int order)
{
    // Second order Markov Chain implementation
    std::map<char, std::map<char, double> > initial_matrix;
    std::map<char, double> initial_vector;
    int total_transitions = 0;
    size_t amount_of_states = states.size();
    char state1;
    char state2;
    MarkovData markov_data;
    // 1st order
    if (1 == order)
    {
        // Create matrix
        size_t index = 0;
        while (index < amount_of_states)
        {
            state1 = states[index];
            if (states.size() != (index + 1))
            {
                state2 = states[index + 1];
            }
            else
            {
                // The last state is alone. There is no transaction, forget about it.
                break;
            }

            if (initial_matrix.end() == initial_matrix.find(state1))
            {
                // First time there is a transition FROM state1
                initial_matrix[state1].clear();
                initial_vector[state1] = 0;
            }

            if(initial_matrix.find(state1) != initial_matrix.end() && initial_matrix[state1].find(state2) != initial_matrix[state1].end())
            {
                double value = initial_matrix[state1][state2];
                initial_matrix[state1][state2] = value + 1;
            }
            else
            {
                // First time there is a transition FROM state 1 to state2
                initial_matrix[state1][state2] = 1;
            }
            initial_vector[state1] += 1;
            total_transitions += 1;
            // Move along
            index += 1;
        }
        Matrix matrix;
        // Normalize using the initial vector
        std::map<char, double> init_vector;
        for (std::map<char,std::map<char,double> >::iterator it1=initial_matrix.begin(); it1 != initial_matrix.end(); ++it1)
        {
            // Create the init vector
            init_vector[it1->first] = initial_vector[it1->first] / total_transitions;
            for (std::map<char, double>::iterator it2=(it1->second).begin(); it2 != (it1->second).end(); ++it2)
            {
                double value = it2->second;
                initial_matrix[it1->first][it2->first] = value / initial_vector[it1->first];
                // Change the style of the matrix
                std::string temp_str;
                temp_str.push_back(it1->first);
                temp_str.push_back(it2->first);
                matrix.update_matrix(temp_str, initial_matrix[it1->first][it2->first]);
            }
        }
        matrix.set_init_vector(init_vector);
        markov_data.matrix = matrix;
        markov_data.init_vector = init_vector;
    }
    return markov_data;
}
