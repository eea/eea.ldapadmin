''' import and exmport functionality '''
import logging
from datetime import datetime
from io import BytesIO
import six.moves.urllib.error
import six.moves.urllib.parse
import six.moves.urllib.request
from six.moves import range
import xlwt

logger = logging.getLogger(__name__)


def attachment_header(filename):
    ''' create the attachment header '''
    assert isinstance(filename, str)
    try:
        value = "filename=%s" % six.moves.urllib.parse.quote(filename)
    except Exception as e:
        # import pdb; pdb.set_trace() not tested exception
        logger.error("Error setting filename %s", str(e))
        value = "filename*=UTF-8''%s" % six.moves.urllib.parse.quote(filename)
    return "attachment; " + value


def set_response_attachment(RESPONSE, filename, content_type, length=None):
    ''' set the response attachment headers '''
    RESPONSE.setHeader('Content-Type', content_type)
    if length is not None:
        RESPONSE.setHeader('Content-Length', length)
    RESPONSE.setHeader('Pragma', 'public')
    RESPONSE.setHeader('Cache-Control', 'max-age=0')
    RESPONSE.setHeader('Content-Disposition', attachment_header(filename))


def excel_headers_to_object(properties):
    """ Converts row data to object, according to header keys """
    # main purpose is to save code lines in logic
    return {
        'id': properties.get('user id'),
        'password': str(properties.get('password')),
        'email': properties.get('e-mail*').lower(),
        'first_name': properties.get('first name*'),
        'last_name': properties.get('last name*'),
        'full_name_native': properties.get('full name (native language)', ''),
        'search_helper': properties.get(
            'search helper (ascii characters only!)', ''),
        'job_title': properties.get('job title'),
        'url': properties.get('url'),
        'postal_address': properties.get('postal address'),
        'phone': properties.get('telephone number*'),
        'mobile': properties.get('mobile telephone number'),
        'fax': properties.get('fax number'),
        'organisation': properties.get('organisation*'),
        'department': properties.get('department'),
        'reasonToCreate': properties.get('reason to create*')
    }


def generate_excel(header, rows):
    ''' generate an excel file
    based on a list of columns (header)
    and a list of lists (rows)'''
    style = xlwt.XFStyle()
    wrapstyle = xlwt.XFStyle()
    wrapstyle.alignment.wrap = 1
    normalfont = xlwt.Font()
    headerfont = xlwt.Font()
    headerfont.bold = True
    style.font = headerfont

    wb = xlwt.Workbook(encoding='utf-8')
    ws = wb.add_sheet('Sheet 1')
    row = 0
    for col in range(0, len(header)):
        ws.col(col).width = 256 * 50
    for col, val in enumerate(header):
        ws.row(row).set_cell_text(col, val, style)
    style.font = normalfont
    for item in rows:
        row += 1
        for col, val in enumerate(item):
            style.num_format_str = 'general'
            try:
                excel_1900 = datetime.strptime('01/01/1900', '%d/%m/%Y')
                style.num_format_str = 'dd/MM/yyyy'
                ws.write(row, col, (val - excel_1900).days + 2, style)
            except TypeError:
                if '\n' in val:
                    ws.write(row, col, val, wrapstyle)
                else:
                    ws.write(row, col, val, style)
    output = BytesIO()
    wb.save(output)
    return output.getvalue()
