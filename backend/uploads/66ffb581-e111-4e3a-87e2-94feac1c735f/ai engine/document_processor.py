import os
import PyPDF2
from docx import Document
from config import Config


class DocumentProcessor:
    """Handles document parsing and text extraction for multiple formats"""

    @staticmethod
    def extract_text_from_pdf(file_path):
        """Extract text from PDF file and count pages"""
        try:
            text = ""
            page_count = 0

            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                page_count = len(pdf_reader.pages)

                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"

            return text.strip(), page_count
        except Exception as e:
            raise Exception(f"Error processing PDF: {str(e)}")

    @staticmethod
    def extract_text_from_docx(file_path):
        """Extract text from DOCX file"""
        try:
            doc = Document(file_path)
            text = ""

            for paragraph in doc.paragraphs:
                text += paragraph.text + "\n"

            # Estimate page count (rough estimate: 500 words per page)
            word_count = len(text.split())
            page_count = max(1, round(word_count / 500))

            return text.strip(), page_count
        except Exception as e:
            raise Exception(f"Error processing DOCX: {str(e)}")

    @staticmethod
    def extract_text_from_txt(file_path):
        """Extract text from TXT file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                text = file.read()

            # Estimate page count based on character count
            char_count = len(text)
            page_count = max(1, round(char_count / Config.CHARS_PER_PAGE))

            return text.strip(), page_count
        except UnicodeDecodeError:
            # Try with different encoding
            try:
                with open(file_path, 'r', encoding='latin-1') as file:
                    text = file.read()
                char_count = len(text)
                page_count = max(1, round(char_count / Config.CHARS_PER_PAGE))
                return text.strip(), page_count
            except Exception as e:
                raise Exception(f"Error processing TXT file: {str(e)}")
        except Exception as e:
            raise Exception(f"Error processing TXT file: {str(e)}")

    @staticmethod
    def extract_code_from_file(file_path):
        """Extract code from code files with language detection"""
        try:
            # Detect file extension
            file_extension = os.path.splitext(file_path)[1].lower().lstrip('.')

            # Try multiple encodings
            encodings = ['utf-8', 'utf-16', 'latin-1', 'ascii']
            code_content = None

            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as file:
                        code_content = file.read()
                    break
                except (UnicodeDecodeError, UnicodeError):
                    continue

            if code_content is None:
                raise Exception(
                    "Unable to decode file with supported encodings")

            # Count lines
            line_count = len(code_content.split('\n'))

            # Estimate "page count" (100 lines = 1 page)
            page_count = max(1, round(line_count / Config.CODE_LINES_PER_PAGE))

            # Detect language
            language = Config.LANGUAGE_MAP.get(file_extension, 'Unknown')

            return code_content.strip(), page_count, line_count, language, file_extension
        except Exception as e:
            raise Exception(f"Error processing code file: {str(e)}")

    @staticmethod
    def process_document(file_path):
        """
        Process document based on file extension and return text with page count

        Returns:
            For regular documents: tuple: (text_content, page_count)
            For code files: tuple: (code_content, page_count, line_count, language, extension)
        """
        file_extension = os.path.splitext(file_path)[1].lower().lstrip('.')

        # Check if it's a code file
        if file_extension in Config.CODE_EXTENSIONS:
            return DocumentProcessor.extract_code_from_file(file_path)

        # Handle regular documents
        if file_extension == 'pdf' or file_path.lower().endswith('.pdf'):
            return DocumentProcessor.extract_text_from_pdf(file_path)
        elif file_extension in ['docx', 'doc']:
            return DocumentProcessor.extract_text_from_docx(file_path)
        elif file_extension == 'txt':
            return DocumentProcessor.extract_text_from_txt(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_extension}")

    @staticmethod
    def validate_document(file_path):
        """Validate that document contains readable text"""
        text, _ = DocumentProcessor.process_document(file_path)

        if not text or len(text.strip()) < 10:
            raise ValueError("Document appears to be empty or unreadable")

        return True
