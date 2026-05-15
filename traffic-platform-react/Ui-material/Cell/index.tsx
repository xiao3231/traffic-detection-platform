/* eslint-disable*/
import React, {useEffect, useState} from 'react'
import styles from './index.module.scss'

export type ICell = {}

export default function Cell(props: ICell) {
  return <img src={require('./assets/image_1.png')} className={styles.image} />
}
