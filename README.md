### 翻译CWE：常见弱点列举 
docx版本

cwe版本: 3.2
翻译效果:

[CWE™社区](http://cwe.mitre.org/index.html)

```python
def write_header(document):
    document.add_heading('CWE翻译计划', 0)
    p = document.add_paragraph('CWE翻译计划 v1.0')
    p.add_run(' by')
    p.add_run(' UESTC').italic = True
    p.add_run(' 418').bold = True
    # 主标题
    document.add_heading('参与贡献人员：', level=1)
    # 副标题
    document.add_paragraph(
        'Mardan & Szg(shang Cr7-joker) & LJIJCJ & Michael Tan',
        style='Intense Quote'
    )
    document.add_page_break()
    document.save('./document/CWE翻译计划.docx')

def document_format(ID, Previous_Entry_Name, Modification_Date, Name_zh, Name_en, Abstraction, Structure, Status, Applicable_Platforms, Description_zh, Description_en, Extended_Description_zh, Extended_Description_en, Background_Detail, Notes):
    document = Document('./document/CWE翻译计划.docx')
    document.add_heading('Weakness ID: ' + ID, level=0)

    one = document.add_paragraph()
    one.add_run('提交日期 ' + Previous_Entry_Name).font.size = Pt(6)
    one.add_run('---> 修改日期 ' + Modification_Date).font.size = Pt(6)
    one.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    one = document.add_paragraph(style='List Bullet')

    one.add_run('Weakness Name:').bold = True
    one.add_run("\n\ten: --> " + Name_en).italic = True
    one.add_run("\n\tzh: -->" + Name_zh).italic = True

    one = document.add_paragraph(style='List Bullet')
    one.add_run('Abstraction: ').bold = True
    one.add_run(Abstraction).italic = True
    one.add_run('\tStructure: ').bold = True
    one.add_run(Structure).italic = True
    one.add_run('\tStatus: ').bold = True
    one.add_run(Status).italic = True
    one = document.add_paragraph(style='List Bullet')
    one.add_run('Applicable_Platforms: ').bold = True
    one.add_run(Applicable_Platforms).italic = True
    one.add_run('\n')   

    document.add_heading('简单描述:', level=3)
    one = document.add_paragraph()
    one.add_run("\t" + Description_zh, 'Body Text Char')
    one.add_run('\n')   

    document.add_heading('Description:', level=3)
    one = document.add_paragraph()
    one.add_run("\t" + Description_en, 'Body Text Char')
    one.add_run('\n')

    document.add_heading('详细描述:', level=3)
    one = document.add_paragraph()
    one.add_run("\t" + Extended_Description_zh, 'Body Text Char')
    one.add_run('\n')   

    document.add_heading('Extended Description:', level=3)
    one = document.add_paragraph()
    one.add_run("\t" + Extended_Description_en, 'Body Text Char')
    one.add_run('\n') 

    document.add_heading('问题背景 (Background Detail):', level=3)
    one = document.add_paragraph()
    one.add_run("\t" + Background_Detail, 'Body Text Char')
    one.add_run('\n')   

    document.add_heading('笔记 (Notes):', level=3)
    one = document.add_paragraph()
    one.add_run("\t" + Notes, 'Body Text Char')
    one.add_run('\n')   

    document.add_page_break()
    document.save('./document/CWE翻译计划.docx')
```
