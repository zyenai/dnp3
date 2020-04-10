package dev.gridio.dnp3.codegen.render.modules

import dev.gridio.dnp3.codegen.model._
import dev.gridio.dnp3.codegen.render._

object FixedSizeVariationModule extends Module {

  def lines(implicit indent : Indentation) : Iterator[String] = {

    def variations : List [FixedSize] = ObjectGroup.all.flatMap {
      g => g.variations.collect {
        case x : FixedSize => x
      }
    }

    "use crate::app::parse::traits::{FixedSize, HasVariation};".eol ++
    "use crate::util::cursor::*;".eol ++
    "use crate::app::gen::enums::CommandStatus;".eol ++
    "use crate::app::types::{ControlCode, Timestamp};".eol ++
    "use crate::app::flags::format::*;".eol ++
    "use crate::app::gen::variations::variation::Variation;".eol ++
    space ++
    spaced(variations.map(v => structDefinition(v)).iterator) ++
    space ++
    spaced(variations.map(v => implFixedSizedVariation(v)).iterator) ++
    space ++
    spaced(variations.map(v => implDisplay(v)).iterator) ++
    space ++
    spaced(variations.map(v => implHasVariation(v)).iterator)
  }

  private def getFieldType(f: FixedSizeFieldType) : String = {
    f match {
      case UInt8Field => "u8"
      case UInt16Field => "u16"
      case UInt32Field => "u32"
      case SInt16Field => "i16"
      case SInt32Field => "i32"
      case Float32Field => "f32"
      case Float64Field => "f64"
      case x : EnumFieldType => x.model.name
      case x : CustomFieldTypeU8 => x.structName
      case TimestampField => "Timestamp"
      case _ => throw new Exception(s"Unhandled field type: ${f.toString}")
    }
  }

  private def getCursorSuffix(f: FixedSizeFieldType) : String = {
    f match {
      case UInt8Field => "u8"
      case UInt16Field => "u16_le"
      case UInt32Field => "u32_le"
      case SInt16Field => "i16_le"
      case SInt32Field => "i32_le"
      case Float32Field => "f32_le"
      case Float64Field => "f64_le"
      case EnumFieldType(_) => "u8"
      case CustomFieldTypeU8(_) => "u8"
      case TimestampField => "u48_le"
      case _ => throw new Exception(s"Unhandled field type: ${f.toString}")
    }
  }

  private def structDefinition(gv : FixedSize)(implicit indent: Indentation): Iterator[String] = {
    commented(gv.fullDesc).eol ++
    "#[derive(Copy, Clone, Debug, PartialEq)]".eol ++
    bracket(s"pub struct ${gv.name}") {
      gv.fields.map(f => s"pub ${f.name}: ${getFieldType(f.typ)},").iterator
    }
  }

  private def implDisplay(gv : FixedSize)(implicit indent: Indentation): Iterator[String] = {
    def fieldDisplayType(typ: FixedSizeFieldType): String = {
      typ match {
        case _ : EnumFieldType => "{:?}"
        case _ : CustomFieldTypeU8 => "{:?}"
        case _ => "{}"
      }
    }

    def fieldNames : String = {
      quoted(gv.fields.map( f=> s"${f.name}: ${fieldDisplayType(f.typ)}").mkString(" "))
    }

    def fieldArgExpression(f: FixedSizeField) : String = {

      def getFlagsType : String = {
        def binary = "BinaryFlagFormatter"
        def analog = "AnalogFlagFormatter"
        def counter = "CounterFlagFormatter"
        def binaryOutputStatus = "BinaryOutputStatusFlagFormatter"
        def doubleBitBinary = "DoubleBitBinaryFlagFormatter"

        gv.parent.groupType match {
          case GroupType.StaticBinary => binary
          case GroupType.BinaryEvent => binary
          case GroupType.AnalogOutputEvent => analog
          case GroupType.StaticAnalogOutputStatus => analog
          case GroupType.AnalogEvent => analog
          case GroupType.StaticAnalog => analog
          case GroupType.StaticCounter => counter
          case GroupType.CounterEvent => counter
          case GroupType.StaticFrozenCounter => counter
          case GroupType.FrozenCounterEvent => counter
          case GroupType.BinaryOutputEvent => binaryOutputStatus
          case GroupType.StaticBinaryOutputStatus => binaryOutputStatus
          case GroupType.StaticDoubleBinary => doubleBitBinary
          case GroupType.DoubleBinaryEvent => doubleBitBinary
          case _ => throw new Exception("unhandled group type")
        }
      }


      if(f.isFlags) {
        s"${getFlagsType}::new(self.flags)"
      } else {
        s"self.${f.name}"
      }
    }

    def fieldArgs : String = {
      gv.fields.map(fieldArgExpression).mkString(", ")
    }

    bracket(s"impl std::fmt::Display for ${gv.name}") {
      bracket("fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result") {
        s"write!(f, ${fieldNames}, ${fieldArgs})".eol
      }
    }
  }

  private def implHasVariation(gv : FixedSize)(implicit indent: Indentation): Iterator[String] = {
    bracket(s"impl HasVariation for ${gv.name}") {
      s"const VARIATION : Variation = Variation::${gv.name};".eol
    }
  }

  private def implFixedSizedVariation(gv : FixedSize)(implicit indent: Indentation): Iterator[String] = {
    def readField(f : FixedSizeField) : String = {
      val inner = s"cursor.read_${getCursorSuffix(f.typ)}()?"
      f.typ match {
        case x : EnumFieldType => s"${x.model.name}::from(${inner})"
        case CustomFieldTypeU8(name) => s"${name}::from(${inner})"
        case TimestampField => s"Timestamp::new(${inner})"
        case _ => inner
      }
    }

    def writeField(f : FixedSizeField) : String = {
      def write(suffix: String) = s"cursor.write_${getCursorSuffix(f.typ)}(self.${f.name}${suffix})?;"
      f.typ match {
        case _ : EnumFieldType => write(".as_u8()")
        case CustomFieldTypeU8(name) => write(".as_u8()")
        case TimestampField => s"self.${f.name}.write(cursor)?;"
        case _ => write("")
      }
    }

    def implRead : Iterator[String] = {
      "#[rustfmt::skip]".eol ++
        bracket(s"fn read(cursor: &mut ReadCursor) -> Result<Self, ReadError>") {
          paren("Ok") {
            bracket(s"${gv.name}") {
              gv.fields.iterator.flatMap { f =>
                s"${f.name}: ${readField(f)},".eol
              }
            }
          }
        }
    }

    def implWrite : Iterator[String] = {
      "#[rustfmt::skip]".eol ++
        bracket(s"fn write(&self, cursor: &mut WriteCursor) -> Result<(), WriteError>") {
            gv.fields.iterator.flatMap { f =>
              writeField(f).eol
            } ++ "Ok(())".eol
        }
    }

    bracket(s"impl FixedSize for ${gv.name}") {
      s"const SIZE: u8 = ${gv.size};".eol ++
      implRead ++
      implWrite
    }
  }

}
