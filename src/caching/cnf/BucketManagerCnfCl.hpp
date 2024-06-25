/*
 * d4
 * Copyright (C) 2020  Univ. Artois & CNRS
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once

//#include <bits/stdint-uintn.h>
#include <sys/types.h>

#include <algorithm>
#include <bitset>
#include <cstring>

#include "BucketInConstruction.hpp"
#include "BucketSortInfo.hpp"
#include "src/caching/CacheManager.hpp"
#include "src/caching/cnf/BucketManagerCnf.hpp"
#include "src/exceptions/BucketException.hpp"
#include "src/problem/ProblemTypes.hpp"
#include "src/utils/Enum.hpp"

namespace d4 {
template <class T>
class BucketManagerCnf;

template <class T>
class BucketManagerCnfCl : public BucketManagerCnf<T> {
 private:
  /**
   * @brief Compute the number of bit needed to encode an unsigned given in
   * parameter.
   *
   * @param v is the value we search for its number of bits.
   * @return the number of bit needed to encode val (~log2(val)).
   */
  inline static unsigned nbBitUnsigned(unsigned v) {
    const unsigned int b[] = {0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000};
    const unsigned int S[] = {1, 2, 4, 8, 16};
    int i;

    unsigned int r = 0;       // result of log2(v) will go here
    for (i = 4; i >= 0; i--)  // unroll for speed...
    {
      if (v & b[i]) {
        v >>= S[i];
        r |= S[i];
      }
    }

    return r + 1;
  }  // nbBitUnsigned

  struct AllocSizeInfo {
    unsigned nbBitEltVar = 0;
    unsigned nbByteStoreVar = 0;
    unsigned nbByteStoreFormula = 0;
    unsigned nbBitStoreLit = 0;
    unsigned totalByte = 0;

    inline void display() {
      std::cout << "nb bit var: " << nbBitEltVar << "\n"
                << "nb bit lit: " << nbBitStoreLit << "\n"
                << "nb byte store var: " << nbByteStoreVar << "\n"
                << "nb byte store formula: " << nbByteStoreFormula << "\n"
                << "total: " << totalByte << "\n";
    }
  };

  std::vector<BucketSortInfo> m_vecBucketSortInfo;
  int m_unusedBucket;
  std::vector<unsigned long int> m_mapVar;

  std::vector<int> m_mustUnMark;
  std::vector<int> m_markIdx;
  std::vector<unsigned> m_idInVecBucket;

  BucketInConstruction m_inConstruction;
  unsigned *m_memoryPosWrtClauseSize;
  unsigned *m_offsetClauses;

 public:
  /**
     Function called in order to initialized variables before using

     @param[in] occM, the CNF occurrence manager
     @param[in] cache, the cache the bucket is linked with.
     @param[in] mdStore, the storing mode for the clause
     @param[in] sizeFirstPage, the amount of bytes for the first page.
     @param[in] sizeAdditionalPage, the amount of bytes for the additional
     pages.
  */
  BucketManagerCnfCl(SpecManagerCnf &occM, CacheManager<T> *cache,
                     ModeStore mdStore, unsigned long sizeFirstPage,
                     unsigned long sizeAdditionalPage,
                     BucketAllocator *bucketAllocator = new BucketAllocator())
      : BucketManagerCnf<T>::BucketManagerCnf(occM, cache, mdStore,
                                              sizeFirstPage, sizeAdditionalPage,
                                              bucketAllocator),
        m_inConstruction(occM) {
    m_mapVar.resize(this->m_nbVarCnf + 1, 0);
    m_markIdx.resize(this->m_nbClauseCnf, -1);
    m_memoryPosWrtClauseSize = new unsigned[occM.getMaxSizeClause() + 1];
    m_offsetClauses = new unsigned[this->m_nbClauseCnf + 1];
  }  // BucketManagerCnfCl

  /**
     Destructor.
   */
  ~BucketManagerCnfCl() {
    delete[] m_memoryPosWrtClauseSize;
    delete[] m_offsetClauses;
  }  // destructor

  /**
   * Get an index to store the distribution information.
   *
   * @param[out] inConstruction, place where we store the bucket in
   * construction.
   *
   * \return the index of a reserved bucket.
   */
  inline int getIdxBucketSortInfo(BucketInConstruction &inConstruction) {
    int ret = m_unusedBucket;

    if (m_unusedBucket == -1) {
      ret = m_vecBucketSortInfo.size();
      m_vecBucketSortInfo.emplace_back(
          BucketSortInfo(inConstruction.nbClauseInDistrib));
    } else
      m_unusedBucket = -1;

    return ret;
  }  // getIdxBucketSortInfo

  /**
   * Push sorted, use the natural order.
   */
  inline void pushSorted(unsigned *tab, unsigned pos, unsigned val) {
    tab[pos] = val;
    for (unsigned i = pos; i > 0; i--)
      if (tab[i] < tab[i - 1])
        std::swap(tab[i], tab[i - 1]);
      else
        break;
  }  // pushSorted

  /**
     It is used in order to construct a sorted residual formula.

     @param[in] l, we considere the clause containing l
     @param[out] inConstruction, place where we store the bucket in
     construction.
  */
  void createDistribWrTLit(const Lit &l, BucketInConstruction &inConstruction) {
    unsigned currentPos = inConstruction.sizeDistrib;  // where we put l.
    inConstruction.sizeDistrib += 2;  // save memory for l and the size.

    // associate a bucket to the literal.
    unsigned counter = 0, nbElt = 0;
    unsigned *tab = &inConstruction.distrib[inConstruction.sizeDistrib];
    int ownBucket = getIdxBucketSortInfo(inConstruction);

    // visit each clause
    m_idInVecBucket.resize(0);
    unsigned nextBucket = m_vecBucketSortInfo.size();

    IteratorIdxClause listIndex =
        this->m_specManager.getVecIdxClause(l, this->m_modeStore);
    for (int *ptr = listIndex.start; ptr != listIndex.end; ptr++) {
      int idx = *ptr;
      if (!this->isKeptClause(idx)) continue;

      assert((unsigned)idx < m_markIdx.size());
      if (m_markIdx[idx] == -1) {
        inConstruction.sizeClauses[idx] = 1;
        m_mustUnMark.push_back(idx);
        m_markIdx[idx] = ownBucket;
        pushSorted(tab, nbElt++, inConstruction.nbClauseInDistrib + counter);
        counter++;
      } else {
        inConstruction.sizeClauses[idx]++;
        BucketSortInfo &b = m_vecBucketSortInfo[m_markIdx[idx]];
        if (!b.counter) {
          assert(nextBucket ==
                 m_vecBucketSortInfo.size() + m_idInVecBucket.size());
          b.redirected = nextBucket++;
          m_idInVecBucket.push_back(m_markIdx[idx]);
        }
        m_markIdx[idx] = b.redirected;
        pushSorted(tab, nbElt++, b.start + b.counter);
        b.counter++;
      }
    }

    inConstruction.sizeDistrib += nbElt;
    assert(inConstruction.sizeDistrib < inConstruction.capacityDistrib);

    m_vecBucketSortInfo.resize(m_vecBucketSortInfo.size() +
                               m_idInVecBucket.size());
    for (auto &bid : m_idInVecBucket) {
      BucketSortInfo &b = m_vecBucketSortInfo[bid];
      assert(b.counter);

      // we split out the bucket.
      m_vecBucketSortInfo[b.redirected].reset(b.start, b.start + b.counter);
      b.start += b.counter;
      b.counter = 0;
    }

    if (!counter)
      m_unusedBucket = ownBucket;
    else {
      m_vecBucketSortInfo[ownBucket].reset(
          inConstruction.nbClauseInDistrib,
          inConstruction.nbClauseInDistrib + counter);
      inConstruction.nbClauseInDistrib += counter;
    }

    if (currentPos == inConstruction.sizeDistrib - 2)
      inConstruction.sizeDistrib -= 2;
    else {
      inConstruction.distrib[currentPos] = l.intern();
      inConstruction.distrib[currentPos + 1] =
          inConstruction.sizeDistrib - currentPos - 2;
    }
  }  // createDistribWrTLit

  /**
     Collect the clause distribution. The result is stored in distrib.

     @param[in] component, the set of variables we consider.
     @param[out] inConstruction, place where we store the bucket in
     construction.

     \return the number of elements we have in the distribution once the
     redundant clauses have been removed.
  */
  inline unsigned collectDistrib(std::vector<Var> &component,
                                 BucketInConstruction &inConstruction) {
    // sort the set of clauses
    for (auto &v : component) {
      if (this->m_specManager.varIsAssigned(v)) continue;
      createDistribWrTLit(Lit::makeLitFalse(v), inConstruction);
      createDistribWrTLit(Lit::makeLitTrue(v), inConstruction);
    }

    // mark the clause we do not keep.
    unsigned realSizeDistrib = inConstruction.sizeDistrib;
    for (auto &idx : m_mustUnMark) {
      BucketSortInfo &b = m_vecBucketSortInfo[m_markIdx[idx]];
      m_markIdx[idx] = -1;
      inConstruction.shiftedSizeClause[b.start] =
          inConstruction.sizeClauses[idx];
      if (b.end != b.start + 1) {
        realSizeDistrib -=
            (b.end - b.start - 1) * this->m_specManager.getCurrentSize(idx);
        for (unsigned j = b.start + 1; j < b.end; j++)
          inConstruction.markedAsRedundant[j] = true;
        b.end = b.start + 1;
      }
    }
    m_mustUnMark.resize(0);

    // shift the clauses indices if requiered.
    unsigned index = 0;
    for (unsigned i = 0; i < inConstruction.nbClauseInDistrib; i++) {
      if (!inConstruction.markedAsRedundant[i]) {
        inConstruction.distribDiffSize[inConstruction.shiftedSizeClause[i]]++;
        inConstruction.shiftedSizeClause[index] =
            inConstruction.shiftedSizeClause[i];
        inConstruction.shiftedIndexClause[i] = index++;
      } else
        inConstruction.shiftedIndexClause[i] = inConstruction.sizeDistrib;
      inConstruction.markedAsRedundant[i] = false;
    }
    inConstruction.nbClauseInDistrib = index;  // resize
    return realSizeDistrib;
  }  // collectDistrib

  /**
     Prepare the data to store a new bucket.

     @param[out] inConstruction, place where we store the bucket in
     construction.
   */
  inline void initSortBucket(BucketInConstruction &inConstruction) {
    inConstruction.reinit();
    m_unusedBucket = -1;
    m_vecBucketSortInfo.resize(0);
  }  // initSortBucket

  /**
   * @brief Display the bucket in construction (for debugging purpose).
   *
   * @param v
   * @param out
   */
  inline void showListBucketSort(std::vector<BucketSortInfo> &v,
                                 std::ostream &out) {
    out << "size = " << v.size() << "\n";
    for (auto &e : v)
      out << "[" << e.start << " " << e.end << " " << e.counter << " "
          << e.redirected << "]\n";
  }  // showListBucketSort

  /**
   * @brief Search for the number of bytes needed to store the different element
   * of the bucket.
   *
   * @param component is the set of variables.
   * @param inConstruction is the bucket that has been constructed.
   * @param nBda
   * @param nbD
   * @param nbEltData
   * @param nbEltDist
   * @return an AllocSizeInfo structure with the requiered information.
   */
  inline AllocSizeInfo computeNeededBytes(
      std::vector<Var> &component, BucketInConstruction &inConstruction) {
    AllocSizeInfo ret;

    // info about the variables.
    ret.nbBitEltVar = nbBitUnsigned(component.back());
    ret.nbByteStoreVar = 1 + (((ret.nbBitEltVar * component.size()) - 1) >> 3);
    unsigned nbByteModeArray = 1 + ((component.back() - 1) >> 3);
    if (nbByteModeArray < ret.nbByteStoreVar) {
      ret.nbByteStoreVar = nbByteModeArray;
      ret.nbBitEltVar = 0;
    }

    ret.nbBitStoreLit = nbBitUnsigned(2 + (component.size() << 1));

    // info about the distribution.
    unsigned cptLitFormula = 0, cptDistrib = 0;
    for (unsigned i = 0; i <= inConstruction.maxSizeClause; i++) {
      if (!inConstruction.distribDiffSize[i]) continue;

      cptDistrib++;
      cptLitFormula += i * inConstruction.distribDiffSize[i];
    }

    ret.nbByteStoreFormula =
        (!cptDistrib)
            ? 0
            : 1 + ((ret.nbBitStoreLit * ((cptDistrib << 1) + cptLitFormula)) >>
                   3);

    ret.totalByte = ret.nbByteStoreVar + ret.nbByteStoreFormula;
    return ret;
  }  // computeNeededBytes

  /**
   * @brief
   *
   * @param p
   * @param val
   * @param nbBit
   * @param remainingBit
   * @return char*
   */
  inline char *addElementInData(char *p, unsigned val, unsigned nbBit,
                                unsigned &remainingBit) {
    if (!remainingBit) {
      remainingBit = 8;
      p++;
    }

#if 0
    std::cout << "val " << val << "\n";
    std::cout << "remaining " << remainingBit << "\n";
    std::cout << "nbBit " << nbBit << "\n";
    std::cout << "=> " << std::bitset<3>(val) << "\n";
#endif
    while (nbBit >= remainingBit) {
      *p |= val & ((1 << remainingBit) - 1);
      val >>= remainingBit;
      nbBit -= remainingBit;
      remainingBit = 8;
      p++;
    }

    // the remaining bits.
    if (nbBit) {
      *p |= val << (remainingBit - nbBit);
      remainingBit -= nbBit;
      assert(remainingBit);
    }

#if 0
    std::cout << "<= " << std::bitset<8>(*p) << "\n";
#endif
    return p;
  }  // addElementInData

  /**
   * @brief Store the variables respecting the information of size concerning
   * the type T to encode each elements and returns the pointer just after the
   * end of the data.
   *
   * @param info gives the information about the way of storing the data.
   * @param data is a pointer to memory where we want to store the data.
   * @param component is the set of variables we want to store.
   * @return the remaining data.
   */
  char *storeVariables(AllocSizeInfo &info, char *data,
                       std::vector<Var> &component) {
    // init the array.
    char *p = data;
    memset(p, 0, info.nbByteStoreVar);

    // fill the array.
    if (!info.nbBitEltVar) {
      for (auto v : component) p[v >> 3] |= ((uint8_t)1) << (v & 7);
    } else {
      unsigned remaining = 8;
      for (auto v : component) {
        assert(v <= component.back());
        p = addElementInData(p, v, info.nbBitEltVar, remaining);
      }
    }

    return &data[info.nbByteStoreVar];
  }  // storeVariables

  /**
     Store the formula representation respecting the information of size
     concerning the type T to encode each elements and returns the pointer
     just after the end of the data.

     Information about the formula is store in member variables:
      - m_sizeDistrib
      - m_distrib

     @param[in] data, the place where we store the information
     @param[in] component, is the set of variables.
     @param[out] inConstruction, place where we store the bucket in
     construction.

     \return a pointer to the end of the data we added
  */
  char *storeClauses(AllocSizeInfo &info, char *data,
                     std::vector<Var> &component,
                     BucketInConstruction &inConstruction) {
    unsigned remaining = 8;
    char *p = data;
    memset(p, 0, info.nbByteStoreFormula);

    // map the variables to their position.
    for (unsigned i = 0; i < component.size(); i++)
      m_mapVar[component[i]] = i + 1;

    // store the different size of the distribution.
    for (unsigned i = 0; i <= inConstruction.maxSizeClause; i++) {
      if (!inConstruction.distribDiffSize[i]) continue;
      p = addElementInData(p, i, info.nbBitStoreLit, remaining);
    }

    // Prepare the offset list regarding p.
    // We also add a zero to separate ditrib from formula.
    unsigned offSet = (8 - remaining) + info.nbBitStoreLit;
    for (unsigned i = 0; i <= inConstruction.maxSizeClause; i++) {
      if (!inConstruction.distribDiffSize[i]) continue;
      m_memoryPosWrtClauseSize[i] = offSet;
      offSet += inConstruction.distribDiffSize[i] * i * info.nbBitStoreLit;
    }

    // allocate an offset for each clauses.
    for (unsigned i = 0; i < inConstruction.nbClauseInDistrib; i++) {
      unsigned &szClause = inConstruction.shiftedSizeClause[i];
      if (!szClause) continue;

      m_offsetClauses[i] = m_memoryPosWrtClauseSize[szClause];
      m_memoryPosWrtClauseSize[szClause] += szClause * info.nbBitStoreLit;
      szClause = 0;  // reinit shiftedSizeClause for the next run.
    }

    // store the formula.
    unsigned i = 0;
    while (i < inConstruction.sizeDistrib) {
      unsigned lit = inConstruction.distrib[i++];
      unsigned l = (m_mapVar[lit >> 1] << 1) | (lit & 1);
      unsigned szLitList = inConstruction.distrib[i++];

      while (szLitList) {
        szLitList--;

        unsigned idx =
            inConstruction.shiftedIndexClause[inConstruction.distrib[i++]];
        if (idx >= inConstruction.nbClauseInDistrib) continue;

        // compute the position in the array.
        unsigned &offSet = m_offsetClauses[idx];
        char *q = &p[offSet >> 3];  // divide by 8
        remaining = 8 - (offSet & 7);

        // add the element and move the offset for the next lit.
        addElementInData(q, l, info.nbBitStoreLit, remaining);
        offSet += info.nbBitStoreLit;
      }
    }

    return &data[info.nbByteStoreFormula];
  }  // storeClauses

  /**
     Transfer the formula store in distib in a table given in parameter.

     @param[in] component, the input variables.
     @param[out] tmpFormula, the place where is stored the formula.
     @param[out] szTmpFormula, to collect the size of the stored formula.
  */
  inline void storeFormula(std::vector<Var> &component, CachedBucket<T> &b) {
    initSortBucket(m_inConstruction);
    collectDistrib(component, m_inConstruction);  // built the sorted formula

    // ask for memory
    AllocSizeInfo sizeInfo = computeNeededBytes(component, m_inConstruction);
    char *data = this->m_bucketAllocator->getArray(sizeInfo.totalByte);

    // store the information about the formula.
    storeVariables(sizeInfo, data, component);
    if (m_inConstruction.nbClauseInDistrib)
      storeClauses(sizeInfo, &data[sizeInfo.nbByteStoreVar], component,
                   m_inConstruction);
    // put the information into the bucket
    DataInfo di(sizeInfo.totalByte, component.size(), sizeInfo.nbBitEltVar,
                sizeInfo.nbBitStoreLit);
    b.set(data, di);
  }  // storeFormula
};
}  // namespace d4
