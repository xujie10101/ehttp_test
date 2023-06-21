#include "Data.h"
#include <math.h>
#include <memory.h>
#include <algorithm>


CData::CData()
:mLength(0),mCapacity(127)
{
   mChars = (char*)malloc(mCapacity+1);
   mChars[mLength] = 0;
}

CData::CData(int capacity, bool)
   : mLength(0),mCapacity(capacity)
{
   mChars = (char*)malloc(mCapacity+1);
   mChars[mLength] = 0;
}

CData::CData(const char* str, int length)
   : mLength(length),mCapacity(length)
{

   mChars = (char*)malloc(mCapacity+1);
   memcpy(mChars, str, length);
   mChars[mLength] = 0;
}

CData::CData(const char* str)
{
   mCapacity = mLength = (NULL==str)?0: strlen(str);
   mChars = (char*)malloc(mCapacity+1);
   memcpy(mChars, str, mLength);
   mChars[mLength] = 0;
}

CData::CData(const std::string& str)
{
	mCapacity = mLength = str.size();
    mChars = (char*)malloc(mCapacity+1);
    memcpy(mChars, str.c_str(), mLength);
    mChars[mLength] = 0;
}

CData::CData(int val)
   : mLength(0),mCapacity(0)
{
   if (val == 0)
   {
      mChars = (char*)malloc(2);
      mChars[0] = '0';
      mChars[1] = 0;
      mLength = 1;
      return;
   }

   bool neg = false;

   int value = val;
   if (value < 0)
   {
      value = -value;
      neg = true;
   }

   int c = 0;
   int v = value;
   while (v /= 10)
   {
      c++;
   }

   if (neg)
   {
      c++;
   }

   mLength = c+1;
   mCapacity = c+1;
   mChars = (char*)malloc(c+2);
   mChars[c+1] = 0;

   v = value;
   while (v)
   {
      mChars[c--] = '0' + v%10;
      v /= 10;
   }
   if (neg)
   {
      mChars[0] = '-';
   }
}

CData::CData(double value, int precision)
   : mChars(0), mLength(0), mCapacity(0)

{
   double v = value;
   bool neg = (value < 0.0);

   if (neg)
   {
      v = -v;
   }

   CData m((unsigned long)v);

   // remainder
   v = v - floor(v);

   int p = precision;
   while (p--)
   {
      v *= 10;
   }

   int dec = (int)floor(v+0.5);

   CData d;

   if (dec == 0)
   {
      d = "0";
   }
   else
   {
      d.resize(precision);
      d.mChars[precision] = 0;
      p = precision;
      // neglect trailing zeros
      bool significant = false;
      while (p--)
      {
         if (dec % 10 || significant)
         {
            significant = true;
            d.mLength++;
            d.mChars[p] = '0' + (dec % 10);
         }
         else
         {
            d.mChars[p] = 0;
         }

         dec /= 10;
      }
   }

   if (neg)
   {
      resize(m.size() + d.size() + 2);
      mChars[0] = '-';
      memcpy(mChars+1, m.mChars, m.size());
      mChars[1+m.size()] = '.';
      memcpy(mChars+1+m.size()+1, d.mChars, d.size() + 1);
      mLength = m.size() + d.size() + 2;
   }
   else
   {
      resize(m.size() + d.size() + 1);
      memcpy(mChars, m.mChars, m.size());
      mChars[m.size()] = '.';
      memcpy(mChars+m.size()+1, d.mChars, d.size() + 1);
      mLength = m.size() + d.size() + 1;
   }
}

CData::CData(unsigned int ulval)
 : mChars(0), mLength(0), mCapacity(0)
{
	if (ulval == 0){
		mChars = (char*)malloc(2);
		mChars[0] = '0';
		mChars[1] = 0;
		mLength = 1;
		return;
	}
	int c = 0;
	int v = ulval;
	while (v /= 10){
		c++;
	}
	mLength = c+1;
	mCapacity = c+1;
	mChars = (char*)malloc(c+2);
	mChars[c+1] = 0;

	v = ulval;
	while (v){
		mChars[c--] = '0' + v%10;
		v /= 10;
	}
}

CData::CData(unsigned long value)
   : mChars(0), mLength(0), mCapacity(0)
{
   if (value == 0)
   {
      mChars = (char*)malloc(2);
      mChars[0] = '0';
      mChars[1] = 0;
      mLength = 1;
      return;
   }

   int c = 0;
   unsigned long v = value;
   while (v /= 10)
   {
      c++;
   }

   mLength = c+1;
   mCapacity = c+1;
   mChars = (char*)malloc(c+2);
   mChars[c+1] = 0;

   v = value;
   while (v)
   {
      mChars[c--] = '0' + v%10;
      v /= 10;
   }
}

CData::CData(char c)
   : mChars(0), mLength(1),
     mCapacity(mLength)
{
   mChars = (char*)malloc(2);
   mChars[0] = c;
   mChars[1] = 0;
}

CData::CData(bool value)
   : mLength(0),  mCapacity(0)
{
   if (value)
   {
	  mLength = 4;
	  mCapacity = 8;
      mChars = (char*)malloc(8);
      memcpy(mChars,"true",mLength);
   }
   else
   {
	  mLength = 5;
	  mCapacity = 8;
      mChars = (char*)malloc(8);
      memcpy(mChars, "false", mLength);
   }
   mChars[mLength] = 0;
}

CData::CData(const CData& rhs)
{
	mCapacity = mLength = rhs.mLength;
    mChars =(char*)malloc(mCapacity+1);
    memcpy(mChars, rhs.mChars, mLength);
	mChars[mLength] = 0;
}

CData::~CData()
{
   free(mChars);
}

CData& CData::operator=(const char* str)
{
   if(str==0){
	   resize(0);
	   mChars[0]=0;
   }else{
	   const int len = strlen(str);
	   if (len > mCapacity){
		   resize(len);
	   }
	   mLength = len;
	   memcpy(mChars, str, mLength);
   }
   mChars[mLength] = 0;
   return *this;
}

CData& CData::operator=(const CData& data )
{
   if (&data != this)
   {
      if (data.size() > mCapacity){
         resize(data.size());
      }
      mLength = data.size();
      memcpy(mChars, data.mChars, data.mLength);
   }
   mChars[mLength] = 0;
   return *this;
}

CData& CData::operator=(int len)
{
	char sTemp[32] = { 0 };
	sprintf(sTemp, "%d", len);
	*this = sTemp;
	return *this;
}

CData& CData::operator=(unsigned int len)
{
	char sTemp[32] = { 0 };
	sprintf(sTemp, "%u", len);
	*this = sTemp;
	return *this;
}

CData& CData::operator=(unsigned long len)
{
	char sTemp[32] = { 0 };
	sprintf(sTemp, "%lu", len);
	*this = sTemp;
	return *this;
}

CData& CData::operator=(float len)
{
	char sTemp[32] = { 0 };
	sprintf(sTemp, "%lf", len);
	*this = sTemp;
	return *this;
}

CData& CData::operator=(double len)
{
	char sTemp[32] = { 0 };
	sprintf(sTemp, "%lf", len);
	*this = sTemp;
	return *this;
}

const char* CData::c_str() const
{
	return mChars;
}

char* CData::s_str() const
{
	return mChars;
}

const char* CData::getCData(char* buf, int len) const
{
   strncpy(buf, mChars, len-1);
   buf[len-1] = 0;
   return buf;
}

char CData::getChar(int i) const
{
   return mChars[i];
}

void
CData::setchar(int i, char c)
{
   if (i >= mLength){
      resize(i+1);
      mLength = i+1;
      memset(mChars + mLength, 0, mCapacity-mLength+1);
   }
   mChars[i] = c;
}

void CData::setData(const char* buf, int len)
{
	if (len > mCapacity) {
		resize(len);
	}

    if (len > 0 && (NULL != buf)){
		memcpy(mChars, buf, len);
    }

   if(len > 0)
      mLength = len;
   else
      mLength = 0;

    mChars[mLength] = 0;
}

char CData::operator[](int i) const
{
   return mChars[i];
}

void CData::resize(int newCapacity)
{
   if (newCapacity < mCapacity){
      return;
   }

   char* oldBuf = mChars;
   mChars = (char*)malloc(newCapacity + 1);
   for (int i = 0; i < mLength; i++){
      mChars[i] = oldBuf[i];
   } 

   free(oldBuf);
   mChars[mLength] = 0;
   mCapacity = newCapacity;
 
}

bool CData::operator==(const char* str) const
{
   return strcmp(mChars, str) == 0;
}

bool CData::operator==( const CData& data) const
{
   return strcmp(mChars, data.mChars) == 0;
}

bool CData::operator!=(const char* str) const
{
   return strcmp(mChars, str) != 0;
}

bool CData::operator!=(const CData& data) const
{
   return strcmp(mChars, data.mChars) != 0;
}

bool CData::operator>(const CData& data) const
{
   return strcmp(mChars, data.mChars) > 0;
}

bool CData::operator<(const CData& data) const
{
   return strcmp(mChars, data.mChars) < 0;
}

bool CData::operator>(const char* data) const
{
   return strcmp(mChars, data) > 0;
}

bool CData::operator<(const char* data) const
{
   return strcmp(mChars, data) < 0;
}

int CData::Compare(const char* str, int len) const
{
   return strncmp(mChars, str, len);
}

int CData::Compare(const CData& data) const
{
   return strncmp(mChars, data.mChars, data.size());
}

int CData::CompareNoCase(const char* str, int length) const
{
   //return strncasecmp(mChars, str, length);
   return strncmp(mChars, str, length);
}

int CData::CompareNoCase(const CData& data) const
{
   //return strncasecmp(mChars, data.mChars, data.size());
   return strncmp(mChars, data.mChars, data.size());
}

CData CData::operator+(const CData& data) const
{
   // reserve
   CData ret(mLength + data.mLength, true);
   memcpy(ret.mChars, mChars, mLength);
   memcpy(ret.mChars+mLength, data.mChars, data.mLength+1);
   ret.mLength = mLength + data.mLength;
   return ret;
}

CData CData::operator+(const char* str) const
{
   // reserve
   int l = strlen(str);
   CData ret(size() + l, true);
   memcpy(ret.mChars, mChars, mLength);
   memcpy(ret.mChars+mLength, str, l+1);
   ret.mLength = mLength + l;
   return ret;
}

CData CData::operator+(const char c) const
{
   // reserve
   CData ret(size() + 1, true);
   memcpy(ret.mChars, mChars, mLength);
   ret.mChars[mLength] = c;
   ret.mChars[mLength+1] = 0;
   ret.mLength = mLength + 1;
   return ret;
}


CData& CData::operator+=(const CData& obj)
{
   if (mCapacity <= mLength + obj.mLength){
      resize(mLength + obj.mLength + 8);
   }

   memcpy(mChars+mLength, obj.mChars, obj.mLength+1);
   mLength += obj.mLength;
   return *this;
}

CData& CData::operator+=(const char* str)
{
   int l = strlen(str);
   if (mCapacity <= mLength + l){
      resize(mLength + l + 8);
   }
   memcpy(mChars+mLength, str,l+1);
   mLength += l;
   return *this;
}

CData& CData::operator+=(int len)
{
	char sTemp[32] = {0};
	sprintf(sTemp,"%d",len);
	*this += sTemp;
	return *this;
}

CData& CData::operator+=(unsigned int len)
{
	char sTemp[32] = {0};
	sprintf(sTemp,"%u",len);
	*this += sTemp;
	return *this;
}

CData& CData::operator+=(unsigned long len)
{
	char sTemp[32] = {0};
	sprintf(sTemp,"%lu",len);
	*this += sTemp;
	return *this;
}

CData& CData::operator+=(const char c)
{
   if (mCapacity < mLength + 1)
   {
      resize(mLength + 1);
   }

   mChars[mLength] = c;
   mChars[mLength+1] = 0;
   mLength += 1;
   return *this;
}


CData& CData::ToLower()
{
   char* p = mChars;
   while ((*p = tolower(*p)) != 0)
   {
      p++;
   }
   return *this;
}

CData& CData::ToUpper()
{
   char* p = mChars;
   while ((*p = toupper(*p)) != 0)
   {
      p++;
   }
   return *this;
}

void CData::Remove()
{
   mLength = 0;
   mChars[0] = 0;
}

CData& CData::Remove(int count,int lf)
{
    if (count < mLength) {
        mLength -= count;
        if (lf) {
            memmove(mChars, mChars + count,mLength);
        }
    }else {
        mLength = 0;
    }       
    mChars[mLength] = 0;

	return *this;
}

CData& CData::Remove(const char* match)
{
    const char* q = match;
    const char* ptr = mChars, * p = mChars;
    while ((*ptr != 0) && (*q != 0)) {
        if (*ptr++ != *q++) {
            ptr = ++p;
            q = match;
        }
    }

    if (*q == 0) {
        mLength = int(p - mChars);
        mChars[mLength] = 0;
    }

    return *this;
}

int CData::ToInt() const
{
   int val = 0;
   char* p = mChars;
   int l = mLength;
   int s = 1;

   while (isspace(*p++))
   {
      l--;
   }
   p--;

   if (*p == '-')
   {
      s = -1;
      p++;
      l--;
   }

   while (l--)
   {
      char c = *p++;
      if ((c >= '0') && (c <= '9'))
      {
         val *= 10;
         val += c - '0';
      }
      else
      {
         return s*val;
      }
   }
   return s*val;
}

long CData::ToLong() const
{
   long val = 0;
   char* p = mChars;
   int l = mLength;
   int s = 1;

   while (isspace(*p++))
   {
      l--;
   }
   p--;

   if (*p == '-')
   {
      s = -1;
      p++;
      l--;
   }

   while (l--)
   {
      char c = *p++;
      if ((c >= '0') && (c <= '9'))
      {
         val *= 10;
         val += c - '0';
      }
      else
      {
         return s*val;
      }
   }

   return s*val;
}

std::string CData::ToString() const
{
   return std::string(mChars);
}

double CData::ToDouble() const
{
   long val = 0;
   char* p = mChars;
   int s = 1;

   while (isspace(*p++));
   p--;

   if (*p == '-')
   {
      s = -1;
      p++;
   }

   while (isdigit(*p))
   {
      val *= 10;
      val += *p - '0';
      p++;
   }

   if (*p == '.')
   {
      p++;
      long d = 0;
      double div = 1.0;
      while (isdigit(*p))
      {
         d *= 10;
         d += *p - '0';
         div *= 10;
         p++;
      }
      return s*(val + d/div);
   }

   return s*val;
}

int CData::substr(const char* ch, int lf)
{
    const char* q = ch;
    const char* ep = mChars + mLength;
    const char* ptr = mChars, * p = mChars;
    while ((*ptr != 0) && (*q != 0) && (ptr < ep)) {
        if (*ptr++ != *q++) {
            ptr = ++p;
            q = ch;
        }
    }

    if (*q == 0) {
        if (lf) {
            mLength = int(p - mChars);
        }
        else {
            int len = strlen(ch);
            mLength = (ep - p) - len;
            memmove(mChars, p + len,mLength);
        }

        mChars[mLength] = 0;

        return 0;
    }
    return CDATA_NPOS;
}

int CData::clean(const char* ch, bool bleft)
{
    const char* q = ch;

    const char* str = mChars;

    const char* ptr = str, * p = str;

    while ((*ptr != 0) && (*q != 0)) {
        if (*ptr++ != *q++) {
            ptr = ++p;
            q = ch;
        }
    }
    if (*q == 0) {
        if (true == bleft) {
            mLength = (p - mChars);
            mChars[mLength] = '\0';
        }
        else {
            mLength = mLength - (ptr - mChars);
            memmove(mChars, ptr, mLength);
            mChars[mLength] = '\0';
        }
        return 0;
    }
    return -1;
}

int CData::substr(const char* fch, const char* lch)
{
    const char* fstr = fch, * lstr = lch;
    const char* eptr = mChars + mLength;
    const char* fptr = mChars;

    {
        const char* p = mChars;

        while ((*fptr != 0) && (*fstr != 0) && (fptr != eptr)) {
            if (*fptr++ != *fstr++) {
                fptr = ++p;
                fstr = fch;
            }
        }
    }

    const char* tptr = fptr;
    {
        const char* p = fptr;
        while ((*tptr != 0) && (*lstr != 0) && (tptr != eptr)) {
            if (*tptr++ != *lstr++) {
                tptr = ++p;
                lstr = lch;
            }
        }
    }

    if (0 == *fstr) {
        if (*lstr == 0) {
            mLength = (tptr - fptr) - strlen(lch);
            memmove(mChars, fptr, mLength);
        }
        else {
            mLength = (eptr - fptr);
            memmove(mChars, fptr, mLength);
        }

        mChars[mLength] = 0;

        return 0;
    }

    return CDATA_NPOS;
}

int CData::substr(CData& obj, const char* ch, int lf)
{
    const char* q = ch;
    const char* ep = mChars + mLength;
    const char* ptr = mChars, * p = mChars;
    while ((*ptr != 0) && (*q != 0) && (ptr < ep)) {
        if (*ptr++ != *q++) {
            ptr = ++p;
            q = ch;
        }
    }
    if (*q == 0) {
        if (lf) {
            obj.setData(mChars, p - mChars);
        }
        else {
            int len = strlen(ch);
            obj.setData(p + len, (ep - p) - len);
        }
        return 0;
    }
    return CDATA_NPOS;
}

int CData::substr(CData& obj, const char* fch, const char* lch)
{
    const char* fstr = fch, * lstr = lch;
    const char* eptr = mChars + mLength;
    const char* fptr = mChars;

    {
        const char* p = mChars;

        while ((*fptr != 0) && (*fstr != 0) && (fptr != eptr)) {
            if (*fptr++ != *fstr++) {
                fptr = ++p;
                fstr = fch;
            }
        }
    }

    const char* tptr = fptr;
    {
        const char* p = fptr;
        while ((*tptr != 0) && (*lstr != 0) && (tptr != eptr)) {
            if (*tptr++ != *lstr++) {
                tptr = ++p;
                lstr = lch;
            }
        }
    }

    if (0 == *fstr) {
        if (*lstr == 0) {
            obj.setData(fptr, (tptr - fptr) - strlen(lch));
        }
        else {
            obj.setData(fptr, (eptr - fptr));
        }
        return 0;
    }

    return CDATA_NPOS;
}

int CData::substr(CData& objKey, CData& objval, const char* ch)
{
    const char* q = ch;
    const char* ep = mChars + mLength;
    const char* ptr = mChars, * p = mChars;
    while ((*ptr != 0) && (*q != 0) && (ptr < ep)) {
        if (*ptr++ != *q++) {
            ptr = ++p;
            q = ch;
        }
    }

    if (*q == 0) {
        int len = strlen(ch);
        objKey.setData(mChars, p - mChars);
        objval.setData(p + len, (ep - p) - len);
        return 0;
    }

    return CDATA_NPOS;
}

int CData::substr(const char* fch, const char* lch, CData& obj)
{
    const char* fstr = fch, * lstr = lch;
    const char* pEnd = mChars + mLength;

    const char* Fptr = mChars;
    {
        const char* p = mChars;

        while ((*Fptr != 0) && (*fstr != 0) && (Fptr != pEnd)) {
            if (*Fptr++ != *fstr++) {
                Fptr = ++p;
                fstr = fch;
            }
        }
    }

    const char* Eptr = Fptr;
    {
        const char* p = Fptr;
        while ((*Eptr != 0) && (*lstr != 0) && (Eptr != pEnd)) {
            if (*Eptr++ != *lstr++) {
                Eptr = ++p;
                lstr = lch;
            }
        }
    }

    if (0 == *fstr) {
        if (*lstr == 0) {
            obj.setData(Fptr, (Eptr - Fptr) - strlen(lch));
        }
        else {
            obj.setData(Fptr, (pEnd - Fptr));
        }
        return 0;
    }

    return -1;
}

int CData::strTok(CData& obj, const char* ch) {
    const char* str = ch;
    const char* pEnd = mChars + mLength;
    const char* pBegin = mChars;

    const char* Fptr = mChars;
    
    const char* p = mChars;

	while ((*Fptr != 0) && (*str != 0) && (Fptr != pEnd)) {
		if (*Fptr++ != *str++) {
			Fptr = ++p;
			str = ch;
		}
	}

    if (0 == *str) {
        obj.setData(pBegin,p-pBegin);
        mLength = (pEnd - p) - strlen(ch);
        memmove(mChars, Fptr, mLength);
        mChars[mLength] = 0;
        return 0;
    }
    else {
        obj.setData(mChars, mLength);
    }

    return -1;
}


int CData::rfind(const CData& match) const
{
    return rfind(match.c_str());
}

int CData::find(const CData& match) const
{
    return find(match.c_str());
}

int CData::find(const char* match) const
{
    const char* q = match;
    const char* str = mChars;
    const char* ptr = str, * p = str;

    while ((*ptr != 0) && (*q != 0)) {
        if (*ptr++ != *q++) {
            ptr = ++p;
            q = match;
        }
    }

    if (*q == 0) {
        return (p - mChars);
    }

    return CDATA_NPOS;
}

int CData::rfind(const char* match) const
{
    int nlen = strlen(match);
    for (int i = mLength - nlen; i > 0; i--) {
        if (!memcmp(mChars + i, match, nlen)) {
            return i;
        }
    }
    return CDATA_NPOS;
}

CData& CData::trim()
{
    char* begin = mChars;
    char* end = mChars + mLength - 1;

    while (isspace(*begin)) begin++;
    while (isspace(*end) && end >= begin) end--;

    mLength = end - begin + 1;

    if (begin > mChars) {
        memmove(mChars, begin, mLength);
    }

    mChars[mLength] = 0;

    return *this;
}

const char* CData::find_first(const char* match)
{
	const char* q = match;
	const char* ptr = mChars, * p = mChars;
	while ((*ptr != 0) && (*q != 0)) {
		if (*ptr++ != *q++) {
			ptr = ++p;
			q = match;
		}
	}
	if (*q == 0) {
		return p;
	}
	return 0;
}

const char* CData::find_last(const char* match)
{
    return find_last_chars(mChars, match);
}

char* skip_space(char* p)
{
    while (*p != '\0' && *p == ' ')
        ++p;
    return p;
}

int  get_next_word(const char* data, char* dst, int* size)
{
    int i = 0;
    while (data[i] != 0)
    {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            memcpy(dst, data, i);
            dst[*size = i] = '\0';
            return 0;
        }
        i++;
    }
    return -1;
}

int split_char(char* data, char** key, char** value, const char* ch)
{
    char* split = 0;

    *value = *key = 0;

    if (!(split = strstr(data, ch))) {
        return -1;
    }

    *split = '\0';

    split = split + strlen(ch);

    *value = skip_space(split);

    *key = data;

    return 0;
}

const char* find_first_chars(const char* str,const char* ch)
{
    const char* q = ch;
    const char* p = str, * p1 = str;

    while ((*p != 0) && (*q != 0)) {
        if (*p++ != *q++) {
            p = ++p1;
            q = ch;
        }
    }

    if (*q == 0) {
        return (p1 + strlen(ch));
    }

    return 0;
}

const char* find_last_chars(const char* str, const char* ch)
{
    const char* q = ch;
    const char* p = str, * p1 = str;

    while ((*p != 0) && (*q != 0)) {
        if (*p++ != *q++) {
            p = ++p1;
            q = ch;
        }
    }
    if (*q == 0) {
        p = p1 + strlen(ch);
        const char* ptr = NULL;
        if (!(ptr = find_last_chars(p, ch))) {
            return p;
        }
        return ptr;
    }
    return str;
}

const char* GetUrlPath(const char* str, const char* delim)
{
    if (NULL == str || delim == NULL) {
        return str;
    }

    const char* q = delim;
    const char* p = str, * lp = str;

    while ((*p != 0) && (*q != 0)) {
        if (*p++ != *q++) {
            p = ++lp;
            q = delim;
        }
    }
    if (*q == 0) {
        p = lp + strlen(delim);
        const char* ptr = NULL;
        if (!(ptr = GetUrlPath(p, delim))) {
            return p;
        }
        return ptr;
    }
    return str;
}