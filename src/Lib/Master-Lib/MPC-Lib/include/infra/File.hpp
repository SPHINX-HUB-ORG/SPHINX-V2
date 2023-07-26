/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


// Scanner Object for C++ - Scanner++

// Copyright (C) 2009, 2010, 2011, 2012, 2013, 2014
// scannerpp.sourceforge.net
//
// This file is part of the Scanner++ Library v0.98.  This library is free
// software; you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License v3 as published by the
// Free Software Foundation.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License v3 for more details.

// You should have received a copy of the GNU Lesser General Public License v3
// along with this library; see the file COPYING.  If not, write to the Free
// Software Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
// USA.

#ifndef SCANNERPP_FILE_H_
#define SCANNERPP_FILE_H_

#include<fstream>
#include<string>

using namespace std;
#include<iostream>

namespace scannerpp
{

	class FileNotFound
	{
	private:
		string file;
	public:
		FileNotFound(string str) :
			file(str)
		{
		}
		string getFile()
		{
			return file;
		}
	};

	class File
	{
	public:
		std::ifstream* file;
		string filename;

		File(string _filename)
		{
			filename = _filename;

			// ====================
			// check if file exists
			// ====================

			std::fstream foo;

			foo.open(filename.c_str());

			if (foo.is_open() == true)
				foo.close();
			else
				throw FileNotFound(filename);
			// ===============================

			file = new std::ifstream(filename.c_str(), std::ifstream::in);
		}

		virtual ~File()
		{
			close();
			delete file;
		}

		int get()
		{
			return file->get();
		}

		bool eof()
		{
			return file->eof();
		}

		void close()
		{
			file->close();
		}
	};

} // end namespace scannerpp

#endif /*SCANNERPP_FILE_H_*/
