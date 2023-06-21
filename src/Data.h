#ifndef COMMONDATA_HH
#define COMMONDATA_HH
#include <stdio.h>
#include <string>
#include <string.h>

const int CDATA_NPOS = 0x7fffffff;

class CData
{
public:
	CData();
	virtual ~CData();

	CData( const char* str );
	CData( const CData& data );
	CData( const std::string& str);
	CData( const char* str, int len);
	explicit CData(char c);
	explicit CData(int value);
	explicit CData(bool value);
	explicit CData(int capacity, bool);
	explicit CData(unsigned int value);
	explicit CData(unsigned long value);
	explicit CData(double value, int precision = 4);

	char operator[](int i) const;
	CData& operator=(const char*);
	CData& operator=(const CData&);
	CData& operator=(int);
	CData& operator=(unsigned int);
	CData& operator=(unsigned long);
	CData& operator=(float);
	CData& operator=(double);

	CData  operator+(char) const;
	CData  operator+(const char*) const;
	CData  operator+(const CData&) const;

	CData& operator+=(int);
	CData& operator+=(unsigned int);
	CData& operator+=(unsigned long);
	CData& operator+=(const char);
	CData& operator+=(const char*);
	CData& operator+=(const CData&);

	bool operator>(const CData& ) const;
	bool operator<(const CData& ) const;
	bool operator>(const char* )  const;
	bool operator<(const char* )  const;
	
	bool operator==( const char*)  const;
	bool operator==( const CData&) const;
	bool operator!=( const char*)  const;
	bool operator!=( const CData&) const;
public:
	void Remove();
	CData& trim();
	CData& ToLower();
	CData& ToUpper();
	CData& Remove(const char* match);
	CData& Remove(int count, int lf);

	int ToInt() const;
	long ToLong() const;
	double ToDouble() const;
	std::string ToString() const;

	char* s_str() const;
	const char* c_str() const;

	char getChar(int i) const;
	void setchar(int i, char c);
	void setData(const char* buf, int len);
	void setChar(int i, char c) { setchar(i, c); }	
	const char* getCData(char* buf, int len) const;

	int size() const {return mLength;}
	bool empty() const {return mLength == 0;}
	int capacity() const { return mCapacity; }

	int find(const char* match) const;
	int find(const CData& match) const;

	int rfind(const char* match) const;
	int rfind(const CData& match) const;

	const char* find_first(const char* match);
	const char* find_last(const char* match);

	int Compare(const CData& data) const;
	int Compare(const char* str, int length) const;

	int CompareNoCase(const CData& data) const;
	int CompareNoCase(const char* str, int length) const;
	
	int clean(const char* ch, bool bleft);

	int substr(const char* ch, int lf);
	int substr(const char* fch, const char* lch);

	int substr(CData& obj, const char* ch, int lf);
	int substr(CData& obj, const char* fch,const char* lch);
	int substr(CData& objKey, CData& objval, const char* ch);
	int substr(const char* fch, const char* lch, CData& obj);

	int strTok(CData& obj,const char* ch);

private:
	void resize(int s);
	char*   mChars;
	int		mLength;
	int		mCapacity;
};

char* skip_space(char* p);

const char* GetUrlPath(const char* str, const char* delim);

const char* find_last_chars(const char* str, const char* ch);

const char* find_first_chars(const char* str, const char* ch);

int  get_next_word(const char* data, char* dst, int* size);

int split_char(char* data, char** key, char** value, const char* ch);


/*
 s.find(s1)				//����s�е�һ�γ���s1��λ�ã������أ�����0��

 s.rfind(s1)			//����s�����γ���s1��λ�ã������أ�����0��

 s.find_first_of(s1)    //������s1������һ���ַ���s�е�һ�γ��ֵ�λ�ã������أ�����0��

s.find_last_of(s1)      //������s1������һ���ַ���s�����һ�γ��ֵ�λ�ã������أ�����0��

s.fin_first_not_of(s1)	//����s�е�һ��������s1�е��ַ���λ�ã������أ�����0��

s.fin_last_not_of(s1)	//����s�����һ��������s1�е��ַ���λ�ã������أ�����0��

*/

#endif
