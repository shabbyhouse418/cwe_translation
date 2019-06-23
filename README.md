### 翻译CWE：常见弱点列举

cwe版本: 3.2
翻译效果:
!()[effect.png]


[CWE™社区](http://cwe.mitre.org/index.html)

document.add_heading('Weakness ID: ' + ID, level=0)

    one = document.add_paragraph()
    one.add_run('提交日期 ' + Previous_Entry_Name).font.size = Pt(6)
    one.add_run('---> 修改日期 ' + Modification_Date).font.size = Pt(6)
    one.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    one = document.add_paragraph(style='List Bullet')

    one.add_run('Weakness Name:\n').bold = True
    one.add_run("\ten: --> " + Name_en).italic = True
    one.add_run("\tzh: -->" + Name_zh).italic = True

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
